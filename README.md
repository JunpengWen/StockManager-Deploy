# Restaurant Stock Management System

A comprehensive Flask-based inventory management solution for multi-location restaurant operations with role-based access control and automated workflows.

## 🚀 Features

### 🔐 Authentication & Authorization
- **Multi-Role System**: Owner, Manager, Employee, Server, Line Cook, Prep Cook
- **Session-Based Authentication**: Secure login with authorization workflows
- **Account Approval System**: New user accounts require owner authorization
- **Store-Based Access Control**: Users can only access their assigned store

### 📦 Inventory Management
- **Multi-Store Support**: Manage inventory across multiple restaurant locations
- **Category-Based Organization**: Organize items by categories with user-specific access
- **Stock Level Tracking**: Monitor current, maximum, and reorder levels
- **Image Upload Support**: Add product images with file validation
- **Supplier Management**: Track supplier information and relationships
- **Unit Management**: Support for different measurement units

### 📊 Reporting & Analytics
- **PDF Report Generation**: Automated stock warning reports using ReportLab
- **Stock Update History**: Complete audit trail of all inventory changes
- **Low Stock Alerts**: Automated warnings when items reach reorder levels
- **Comprehensive Update Reports**: Detailed reports for inventory update sessions

### 🔄 Automated Workflows
- **Background Scheduler**: Automated cleanup of old stock history (30-day retention)
- **Batch Operations**: Add items to all stores simultaneously
- **Data Validation**: Comprehensive input validation and error handling

## 🛠️ Tech Stack

- **Backend**: Python 3.7+ / Flask 3.0.2
- **Database**: SQLite with automatic schema management
- **Frontend**: Bootstrap 5.3 + AJAX for responsive design
- **PDF Generation**: ReportLab 4.1.0
- **Task Scheduling**: APScheduler 3.10.4
- **File Handling**: Werkzeug 3.0.1

## 📋 Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Modern web browser

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone [your-repository-url]
cd StockManager-Deploy
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Initialize the Database
```bash
python -c "from app import init_db; init_db()"
```

### 4. Start the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 🌐 Production Deployment

### Amazon Lightsail Deployment (Ubuntu)

This application is production-ready and can be deployed on Amazon Lightsail. See `DEPLOYMENT.md` for detailed instructions.

#### Quick Deployment Steps:

1. **Create a Lightsail Instance:**
   - Platform: Linux/Unix
   - Blueprint: Ubuntu 22.04 LTS
   - Minimum: 1GB RAM recommended

2. **Connect to your instance:**
   ```bash
   ssh ubuntu@your-instance-ip
   ```

3. **Upload your application files** to `/var/www/stockmanager/`

4. **Run the automated deployment script:**
   ```bash
   cd /var/www/stockmanager
   chmod +x deploy.sh
   ./deploy.sh
   ```

   The script will automatically:
   - Install all dependencies
   - Set up virtual environment
   - Configure Gunicorn service
   - Set up Nginx reverse proxy
   - Configure firewall
   - Initialize the database

5. **Access your application:**
   - Visit `http://your-instance-ip` or `http://your-domain.com`

#### Manual Deployment:

For step-by-step manual deployment, see `DEPLOYMENT.md`.

#### Post-Deployment:

1. **Set up SSL/HTTPS (Recommended):**
   ```bash
   sudo apt install -y certbot python3-certbot-nginx
   sudo certbot --nginx -d your-domain.com
   ```

2. **Configure backups:**
   - See `DEPLOYMENT.md` for backup script setup

3. **Change default password:**
   - Login with default credentials and change immediately

#### Service Management:

```bash
# Check application status
sudo systemctl status stockmanager

# View logs
sudo journalctl -u stockmanager -f

# Restart application
sudo systemctl restart stockmanager

# Restart Nginx
sudo systemctl restart nginx
```

## 🔑 Default Login

After installation, you can log in with the default owner account:
- **Username**: `owner`
- **Password**: `ownerpass`

**⚠️ Important**: Change the default password immediately after first login!

## 📁 Project Structure

```
StockManager-Deploy/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── DEPLOYMENT.md         # Detailed deployment guide
├── deploy.sh             # Automated deployment script for Lightsail
├── gunicorn_config.py    # Gunicorn production configuration
├── setup_secret_key.py   # Secret key generation utility
├── instance/
│   └── stock_manager.db  # SQLite database (created automatically)
├── static/
│   └── uploads/          # Product image uploads
└── templates/
    ├── userlogin.html    # Login page
    ├── register.html     # User registration
    ├── owner_dashboard.html      # Owner interface
    ├── manager_dashboard.html    # Manager interface
    └── employee_dashboard.html   # Employee interface
```

## 🔧 Configuration

### Setting Flask Secret Key (REQUIRED for Production)

The Flask secret key is used for session management and security. **You must set a strong secret key in production!**

#### Option 1: Generate and Set Secret Key (Recommended)

1. **Generate a secure secret key:**
   ```bash
   python setup_secret_key.py
   ```
   This will generate a secure random key and show you how to set it.

2. **Set the environment variable:**

   **Windows (PowerShell):**
   ```powershell
   $env:FLASK_SECRET_KEY="your-generated-secret-key-here"
   ```

   **Windows (Command Prompt):**
   ```cmd
   set FLASK_SECRET_KEY=your-generated-secret-key-here
   ```

   **Linux/Mac:**
   ```bash
   export FLASK_SECRET_KEY="your-generated-secret-key-here"
   ```

3. **For permanent setup (Windows):**
   - Open System Properties → Environment Variables
   - Add new System Variable:
     - Variable name: `FLASK_SECRET_KEY`
     - Variable value: `your-generated-secret-key-here`

4. **For permanent setup (Linux/Mac):**
   Add to `~/.bashrc` or `~/.zshrc`:
   ```bash
   export FLASK_SECRET_KEY="your-generated-secret-key-here"
   ```

#### Option 2: Using .env file (Alternative)

1. Copy `.env.example` to `.env`:
   ```bash
   copy .env.example .env  # Windows
   cp .env.example .env    # Linux/Mac
   ```

2. Generate a secret key:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

3. Edit `.env` and set your secret key:
   ```env
   FLASK_SECRET_KEY=your-generated-secret-key-here
   FLASK_ENV=production
   ```

4. Install python-dotenv (if using .env file):
   ```bash
   pip install python-dotenv
   ```

   Then add to `app.py` at the top:
   ```python
   from dotenv import load_dotenv
   load_dotenv()
   ```

#### ⚠️ Security Notes:
- **Never commit `.env` file or secret keys to version control**
- Use a different secret key for each environment (development, staging, production)
- The app will auto-generate a temporary key if `FLASK_SECRET_KEY` is not set (development only)
- For production, always set a strong, unique secret key

### Database Configuration
The application uses SQLite by default. The database file is automatically created in the `instance/` directory.

## 👥 User Roles & Permissions

### Owner
- Full system access across all stores
- User account management and authorization
- System configuration (categories, suppliers, units, stores)
- Generate reports for any store

### Manager
- Manage inventory for assigned store
- View stock history and reports
- Limited user management within store

### Employee/Server/Line Cook/Prep Cook
- Update stock levels for assigned categories
- View inventory for assigned store
- Limited to specific item categories

## 🔒 Security Features

- Session-based authentication
- Role-based access control
- Store-level data isolation
- Input validation and sanitization
- File upload security (image validation)

## 📈 Usage Examples

### Adding Inventory Items
1. Log in as Owner or Manager
2. Navigate to Management → Add Inventory Item
3. Fill in item details (name, category, stock levels, supplier)
4. Select target store(s)
5. Upload product image (optional)

### Managing Stock Levels
1. Log in with appropriate role
2. View current inventory
3. Click on item to update stock level
4. Enter new quantity
5. System automatically tracks changes and generates warnings

### Generating Reports
1. Access report generation from dashboard
2. Select report type (stock warnings, update history)
3. Choose store and date range
4. Download PDF report

## 🚨 Important Security Notes

⚠️ **Security Features:**
- ✅ **Passwords are hashed** using Werkzeug's PBKDF2 with SHA-256
- ✅ **Session-based authentication** with secure session management
- ✅ **Role-based access control** with store-level isolation
- ⚠️ **Default secret key** should be changed in production (auto-generated if not set)
- ⚠️ **HTTPS/SSL** should be enabled for production deployment (use Certbot)
- ⚠️ **Default owner password** (`ownerpass`) must be changed after first login
- ✅ **Input validation** and sanitization on all user inputs
- ✅ **File upload security** with extension validation

**Production Security Checklist:**
- [ ] Strong `FLASK_SECRET_KEY` set in environment variables
- [ ] Default owner password changed
- [ ] SSL/HTTPS certificate installed
- [ ] Firewall configured (UFW)
- [ ] Regular backups configured
- [ ] Database file permissions secured
- [ ] System updates scheduled

## 🔧 Development

### Running in Development Mode
```bash
export FLASK_ENV=development
python app.py
```

The application will run on `http://localhost:5000` with debug mode enabled.

### Production Mode

For production, use Gunicorn:
```bash
gunicorn --config gunicorn_config.py app:app
```

Or use the systemd service (after deployment):
```bash
sudo systemctl start stockmanager
```

### Database Reset
```bash
rm instance/stock_manager.db
python -c "from app import init_db; init_db()"
```

**⚠️ Warning:** This will delete all data. Use with caution in production.

## 📝 API Endpoints

The application provides RESTful API endpoints for:
- User authentication and management
- Inventory CRUD operations
- Stock level updates
- Report generation
- Category and supplier management

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

[Add your license information here]

## 🆘 Support & Troubleshooting

### Common Issues

**Application not accessible:**
- Check Lightsail firewall settings (HTTP 80, HTTPS 443)
- Verify service status: `sudo systemctl status stockmanager`
- Check Nginx: `sudo systemctl status nginx`
- View logs: `sudo journalctl -u stockmanager -n 50`

**Database errors:**
- Ensure database directory exists: `mkdir -p instance`
- Reinitialize: `python -c "from app import init_db; init_db()"`
- Check permissions: `sudo chmod -R 775 instance/`

**Permission errors:**
```bash
sudo chown -R $USER:www-data /var/www/stockmanager
sudo chmod -R 755 /var/www/stockmanager
sudo chmod -R 775 /var/www/stockmanager/instance
sudo chmod -R 775 /var/www/stockmanager/static
```

### Getting Help

For issues and questions:
1. Check the documentation (`DEPLOYMENT.md` for deployment issues)
2. Review application logs: `sudo journalctl -u stockmanager -f`
3. Check Nginx logs: `sudo tail -f /var/log/nginx/error.log`
4. Review existing issues
5. Create a new issue with detailed information

## 🔄 Changelog

### Version 1.0.0
- Initial release
- Multi-store inventory management
- Role-based access control
- PDF report generation
- Automated stock tracking
- Password hashing with PBKDF2
- Amazon Lightsail deployment support
- Automated deployment script
- Gunicorn production configuration
- Background task scheduler for data cleanup

---

## 📚 Additional Resources

- **Deployment Guide**: See `DEPLOYMENT.md` for detailed Lightsail deployment instructions
- **Production Configuration**: `gunicorn_config.py` contains production server settings
- **Deployment Script**: `deploy.sh` automates the entire deployment process

**Note**: This is a production-ready system. Ensure you:
- Set a strong `FLASK_SECRET_KEY` in production
- Enable HTTPS/SSL
- Change default passwords
- Configure regular backups
- Keep the system updated
