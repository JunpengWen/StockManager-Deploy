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

### Environment Variables (Recommended)
Create a `.env` file in the project root:
```env
FLASK_SECRET_KEY=your-secure-secret-key-here
FLASK_ENV=production
```

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

⚠️ **Current Security Considerations:**
- Passwords are stored in plain text (should be hashed in production)
- Default secret key should be changed
- Consider implementing HTTPS for production deployment
- Regular security updates recommended

## 🔧 Development

### Running in Development Mode
```bash
export FLASK_ENV=development
python app.py
```

### Database Reset
```bash
rm instance/stock_manager.db
python -c "from app import init_db; init_db()"
```

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

## 🆘 Support

For issues and questions:
1. Check the documentation
2. Review existing issues
3. Create a new issue with detailed information

## 🔄 Changelog

### Version 1.0.0
- Initial release
- Multi-store inventory management
- Role-based access control
- PDF report generation
- Automated stock tracking

---

**Note**: This is a production-ready system but should be deployed with proper security measures in place.
