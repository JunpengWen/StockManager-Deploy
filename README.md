# Restaurant Stock Management System

A comprehensive Flask-based inventory management solution for multi-location restaurant operations.

![System Overview](screenshots/dashboard-overview.png) *Add relevant screenshots*

## Key Features

### Role-Based Access Control
- **Roles**: Owner, Manager, Employee, Server, Line Cook, Prep Cook
- **Authentication**: Session-based with authorization workflows
- **New User Approval**: Owner authorization required for new accounts

### Inventory Management
- 🗃️ Category-based item organization
- 📈 Stock level tracking (Current/Max/Reorder levels)
- 📸 Item image uploads with file validation
- 📮 Supplier information tracking
- 🔄 Automated stock level audits

### Automated Workflows
- ⚠️ Low stock warnings and PDF reports
- 📅 Daily inventory checklists
- 📊 Stock update history tracking
- 💾 Automated SQLite database backups

### Advanced Features
- 📄 PDF report generation with ReportLab
- 🔍 Full audit trail of all stock changes
- 📱 Mobile-optimized responsive UI
- 🔄 RESTful API endpoints

## Tech Stack
- **Backend**: Python/Flask
- **Database**: SQLite with schema versioning
- **Frontend**: Bootstrap 5 + AJAX
- **PDF Generation**: ReportLab
- **Security**: CSRF protection, session management

## Installation
```bash
# Clone repository
git clone [repository-url]
cd stock-manager

# Install dependencies
pip install flask reportlab

# Initialize database
python -c "from app import init_db; init_db()"

# Start application
python app.py