#!/bin/bash
# Deployment script for Amazon Lightsail
# Run this script on your Lightsail instance after initial setup

set -e  # Exit on error

echo "========================================="
echo "Stock Manager Deployment Script"
echo "========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}Please do not run as root. Use a regular user with sudo privileges.${NC}"
    exit 1
fi

APP_DIR="/var/www/stockmanager"
VENV_DIR="$APP_DIR/venv"

echo -e "${GREEN}Step 1: Updating system packages...${NC}"
sudo apt update
sudo apt upgrade -y

echo -e "${GREEN}Step 2: Installing required packages...${NC}"
sudo apt install -y python3 python3-pip python3-venv nginx git

echo -e "${GREEN}Step 3: Creating application directory...${NC}"
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR
cd $APP_DIR

echo -e "${GREEN}Step 4: Setting up virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

echo -e "${GREEN}Step 5: Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

echo -e "${GREEN}Step 6: Creating necessary directories...${NC}"
mkdir -p instance static/uploads
mkdir -p /var/log/stockmanager
sudo chown $USER:$USER /var/log/stockmanager

echo -e "${YELLOW}Step 7: Setting up environment variables...${NC}"
if [ ! -f .env ]; then
    echo "Creating .env file..."
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    cat > .env << EOF
FLASK_SECRET_KEY=$SECRET_KEY
FLASK_ENV=production
EOF
    echo -e "${GREEN}Generated and saved secret key to .env file${NC}"
else
    echo -e "${YELLOW}.env file already exists, skipping...${NC}"
fi

echo -e "${GREEN}Step 8: Initializing database...${NC}"
python3 -c "from app import init_db; init_db()"

echo -e "${GREEN}Step 9: Setting permissions...${NC}"
sudo chown -R $USER:www-data $APP_DIR
sudo chmod -R 755 $APP_DIR
sudo chmod -R 775 $APP_DIR/instance
sudo chmod -R 775 $APP_DIR/static

echo -e "${YELLOW}Step 10: Creating systemd service...${NC}"
read -p "Enter your instance IP or domain name: " SERVER_NAME

sudo tee /etc/systemd/system/stockmanager.service > /dev/null << EOF
[Unit]
Description=Stock Manager Gunicorn daemon
After=network.target

[Service]
User=$USER
Group=www-data
WorkingDirectory=$APP_DIR
Environment="PATH=$VENV_DIR/bin"
EnvironmentFile=$APP_DIR/.env
ExecStart=$VENV_DIR/bin/gunicorn --config $APP_DIR/gunicorn_config.py app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}Step 11: Configuring Nginx...${NC}"
sudo tee /etc/nginx/sites-available/stockmanager > /dev/null << EOF
server {
    listen 80;
    server_name $SERVER_NAME;

    client_max_body_size 16M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 120s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }

    location /static {
        alias $APP_DIR/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/stockmanager /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

echo -e "${GREEN}Step 12: Configuring firewall...${NC}"
sudo ufw allow 'Nginx Full'
sudo ufw allow OpenSSH
echo "y" | sudo ufw enable

echo -e "${GREEN}Step 13: Starting services...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable stockmanager
sudo systemctl start stockmanager
sudo systemctl restart nginx

echo -e "${GREEN}Step 14: Testing configuration...${NC}"
sudo nginx -t
sudo systemctl status stockmanager --no-pager

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Deployment completed successfully!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "Your application should be accessible at: http://$SERVER_NAME"
echo ""
echo "Useful commands:"
echo "  Check status: sudo systemctl status stockmanager"
echo "  View logs:    sudo journalctl -u stockmanager -f"
echo "  Restart:      sudo systemctl restart stockmanager"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Set up SSL certificate: sudo certbot --nginx -d $SERVER_NAME"
echo "2. Change default owner password after first login"
echo "3. Configure backups (see DEPLOYMENT.md)"
echo ""

