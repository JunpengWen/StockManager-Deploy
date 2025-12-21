# Deployment Guide: Amazon Lightsail (Linux/Unix)

This guide will help you deploy the Stock Manager application to Amazon Lightsail.

## Prerequisites

- Amazon Lightsail account
- Domain name (optional, but recommended)
- SSH access to your Lightsail instance

## Step 1: Create Lightsail Instance

1. Log in to [Amazon Lightsail Console](https://lightsail.aws.amazon.com/)
2. Click "Create instance"
3. Choose:
   - **Platform**: Linux/Unix
   - **Blueprint**: Ubuntu 22.04 LTS (or latest)
   - **Instance plan**: Choose based on your needs (minimum 1GB RAM recommended)
4. Name your instance and click "Create instance"

## Step 2: Connect to Your Instance

1. In Lightsail console, click on your instance
2. Click "Connect using SSH" or use SSH from your terminal:

```bash
ssh ubuntu@your-instance-ip
```

Or download the SSH key from Lightsail and use:
```bash
ssh -i /path/to/key.pem ubuntu@your-instance-ip
```

## Step 3: Initial Server Setup

### Update system packages
```bash
sudo apt update
sudo apt upgrade -y
```

### Install required packages
```bash
sudo apt install -y python3 python3-pip python3-venv nginx git
```

### Install PostgreSQL (optional, if you want to migrate from SQLite later)
```bash
sudo apt install -y postgresql postgresql-contrib
```

## Step 4: Deploy Your Application

### Create application directory
```bash
sudo mkdir -p /var/www/stockmanager
sudo chown ubuntu:ubuntu /var/www/stockmanager
cd /var/www/stockmanager
```

### Clone or upload your application
**Option A: Using Git**
```bash
git clone https://github.com/your-username/StockManager-Deploy.git .
```

**Option B: Using SCP (from your local machine)**
```bash
# From your local machine
scp -i /path/to/key.pem -r /path/to/StockManager-Deploy ubuntu@your-instance-ip:/var/www/stockmanager/
```

### Create virtual environment
```bash
cd /var/www/stockmanager
python3 -venv venv
source venv/bin/activate
```

### Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Create necessary directories
```bash
mkdir -p instance static/uploads
```

## Step 5: Configure Environment Variables

### Create .env file
```bash
nano .env
```

Add the following (generate secret key using `python3 -c "import secrets; print(secrets.token_hex(32))"`):
```env
FLASK_SECRET_KEY=your-generated-secret-key-here
FLASK_ENV=production
```

### Or set system environment variables
```bash
sudo nano /etc/environment
```

Add:
```
FLASK_SECRET_KEY=your-generated-secret-key-here
FLASK_ENV=production
```

Then reload:
```bash
source /etc/environment
```

## Step 6: Initialize Database

```bash
source venv/bin/activate
python3 -c "from app import init_db; init_db()"
```

## Step 7: Test the Application

```bash
source venv/bin/activate
python3 app.py
```

Visit `http://your-instance-ip:5000` to test. Press `Ctrl+C` to stop.

## Step 8: Create Gunicorn Service

### Create systemd service file
```bash
sudo nano /etc/systemd/system/stockmanager.service
```

Add the following content:
```ini
[Unit]
Description=Stock Manager Gunicorn daemon
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/var/www/stockmanager
Environment="PATH=/var/www/stockmanager/venv/bin"
Environment="FLASK_SECRET_KEY=your-secret-key-here"
Environment="FLASK_ENV=production"
ExecStart=/var/www/stockmanager/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 --timeout 120 app:app

[Install]
WantedBy=multi-user.target
```

**Important**: Replace `your-secret-key-here` with your actual secret key!

### Enable and start the service
```bash
sudo systemctl daemon-reload
sudo systemctl enable stockmanager
sudo systemctl start stockmanager
sudo systemctl status stockmanager
```

### Useful commands
```bash
# Check status
sudo systemctl status stockmanager

# View logs
sudo journalctl -u stockmanager -f

# Restart service
sudo systemctl restart stockmanager

# Stop service
sudo systemctl stop stockmanager
```

## Step 9: Configure Nginx Reverse Proxy

### Create Nginx configuration
```bash
sudo nano /etc/nginx/sites-available/stockmanager
```

Add the following:
```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    # If using IP only, use:
    # server_name your-instance-ip;

    client_max_body_size 16M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }

    location /static {
        alias /var/www/stockmanager/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

### Enable the site
```bash
sudo ln -s /etc/nginx/sites-available/stockmanager /etc/nginx/sites-enabled/
sudo nginx -t  # Test configuration
sudo systemctl restart nginx
```

## Step 10: Configure Firewall

### Allow HTTP and HTTPS
```bash
sudo ufw allow 'Nginx Full'
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status
```

## Step 11: Set Up SSL/HTTPS (Optional but Recommended)

### Install Certbot
```bash
sudo apt install -y certbot python3-certbot-nginx
```

### Get SSL certificate
```bash
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
```

Follow the prompts. Certbot will automatically configure Nginx.

### Auto-renewal (already set up by certbot)
```bash
sudo certbot renew --dry-run
```

## Step 12: Configure Lightsail Networking

1. Go to Lightsail Console → Your Instance → Networking
2. Add custom ports:
   - **HTTP (80)**: Allow
   - **HTTPS (443)**: Allow
   - **Custom (5000)**: Only if needed (not recommended, use Nginx)

## Step 13: Set Up Domain (Optional)

1. In Lightsail Console → Networking → DNS zones
2. Create DNS zone for your domain
3. Add A record pointing to your instance IP
4. Update nameservers at your domain registrar

## Step 14: Final Configuration

### Set proper permissions
```bash
sudo chown -R ubuntu:www-data /var/www/stockmanager
sudo chmod -R 755 /var/www/stockmanager
sudo chmod -R 775 /var/www/stockmanager/instance
sudo chmod -R 775 /var/www/stockmanager/static
```

### Create log directory
```bash
sudo mkdir -p /var/log/stockmanager
sudo chown ubuntu:ubuntu /var/log/stockmanager
```

## Step 15: Update Application Code

When you need to update the application:

```bash
cd /var/www/stockmanager
source venv/bin/activate

# If using Git
git pull origin main

# Or upload new files via SCP

# Restart the service
sudo systemctl restart stockmanager
```

## Troubleshooting

### Check Gunicorn logs
```bash
sudo journalctl -u stockmanager -n 50 --no-pager
```

### Check Nginx logs
```bash
sudo tail -f /var/log/nginx/error.log
sudo tail -f /var/log/nginx/access.log
```

### Test Gunicorn directly
```bash
cd /var/www/stockmanager
source venv/bin/activate
gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
```

### Check if port is in use
```bash
sudo netstat -tlnp | grep :5000
```

### Restart all services
```bash
sudo systemctl restart stockmanager
sudo systemctl restart nginx
```

## Security Checklist

- [ ] Strong FLASK_SECRET_KEY set
- [ ] Firewall configured (UFW)
- [ ] SSL/HTTPS enabled
- [ ] Database file permissions secured
- [ ] Regular backups configured
- [ ] SSH key authentication (disable password auth)
- [ ] Regular system updates scheduled

## Backup Strategy

### Create backup script
```bash
sudo nano /usr/local/bin/backup-stockmanager.sh
```

Add:
```bash
#!/bin/bash
BACKUP_DIR="/home/ubuntu/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/stockmanager_$DATE.tar.gz /var/www/stockmanager/instance/stock_manager.db
find $BACKUP_DIR -name "stockmanager_*.tar.gz" -mtime +30 -delete
```

Make executable:
```bash
sudo chmod +x /usr/local/bin/backup-stockmanager.sh
```

### Schedule daily backups (crontab)
```bash
crontab -e
```

Add:
```
0 2 * * * /usr/local/bin/backup-stockmanager.sh
```

## Monitoring

### Set up CloudWatch (Lightsail)
1. Go to Lightsail Console → Monitoring
2. Enable metric alarms for:
   - CPU utilization
   - Network in/out
   - Status check failed

## Default Login

After deployment, use the default owner account:
- **Username**: `owner`
- **Password**: `ownerpass`

**⚠️ IMPORTANT**: Change this password immediately after first login!

## Support

For issues, check:
- Application logs: `sudo journalctl -u stockmanager -f`
- Nginx logs: `sudo tail -f /var/log/nginx/error.log`
- System resources: `htop` or `free -h`

