# How to Run Your ERP Project

This guide will help you set up and run your ERP system step by step.

---

## 📋 Prerequisites

Before running the project, ensure you have:

1. **Python 3.12** (or compatible version)
2. **MySQL Server** installed and running
3. **MySQL Database** created (default: `Erp_Db`)
4. **Gmail Account** (for sending emails) with App-Specific Password

---

## 🚀 Step-by-Step Setup

### Step 1: Activate Virtual Environment

You have two virtual environments. Use the main one in the project root:

**On Windows:**
```powershell
# Navigate to project directory
cd "C:\Users\Rimanshi Gupta\OneDrive\Desktop\New folder\Project1\home\extrauser\Desktop\Project1"

# Activate virtual environment
venv\Scripts\Activate.ps1
```

**On Linux/Mac:**
```bash
cd /path/to/Project1
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt.

---

### Step 2: Install Dependencies

If packages are missing, install them:

```bash
pip install flask
pip install mysql-connector-python
pip install python-dotenv
pip install flask-mail
pip install PyJWT
pip install itsdangerous
```

Or install all at once:
```bash
pip install flask mysql-connector-python python-dotenv flask-mail PyJWT itsdangerous
```

---

### Step 3: Set Up Environment Variables

1. **Copy the template:**
   ```bash
   copy env_template.txt .env
   ```
   (On Linux/Mac: `cp env_template.txt .env`)

2. **Generate secure keys:**
   ```python
   python -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_urlsafe(32))"
   python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(32))"
   python -c "import secrets; print('LICENSE_SECRET_KEY=' + secrets.token_urlsafe(32))"
   ```

3. **Edit `.env` file** and fill in all values:

   ```env
   # Flask Configuration
   FLASK_SECRET_KEY=<paste_generated_key_here>
   FLASK_ENV=development
   JWT_SECRET=<paste_generated_key_here>

   # Database Configuration
   DB_HOST=localhost
   DB_USER=root
   DB_PASSWORD=YourNewPassword
   DB_NAME=Erp_Db

   # Email Configuration (Gmail)
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_app_specific_password
   MAIL_DEFAULT_SENDER=your_email@gmail.com

   # Application Configuration
   BASE_URL=http://localhost:5503
   TEMP_PASSWORD=temporary_password_123

   # License Key Configuration
   LICENSE_SECRET_KEY=<paste_generated_key_here>
   ```

   **Important Notes:**
   - Replace `YourNewPassword` with your actual MySQL password
   - For Gmail, you need to create an **App-Specific Password**:
     1. Go to Google Account → Security
     2. Enable 2-Step Verification
     3. Generate App Password
     4. Use that password in `MAIL_PASSWORD`
   - `BASE_URL` should match your server URL (for email links)

---

### Step 4: Set Up MySQL Database

1. **Start MySQL Server** (if not running)

2. **Create the database:**
   ```sql
   CREATE DATABASE Erp_Db;
   USE Erp_Db;
   ```

3. **Create required tables:**

   You'll need to create tables for:
   - `users` - User accounts
   - `files` - File metadata
   - `user_file_access` - File access permissions
   - `user_access` - Feature access permissions
   - `permissions` - Role-based permissions
   - `meetings` - Meeting records
   - `crm_tickets` - Support tickets
   - `employees` - Employee profiles
   - `client_profiles` - Client profiles

   **Note:** If you have SQL schema files, import them. Otherwise, the application will create tables as needed (you may need to adjust the code).

---

### Step 5: Create Required Directories

The application will create these automatically, but you can create them manually:

```bash
mkdir logs
mkdir uploads
```

---

### Step 6: Run the Application

**Option 1: Direct Python execution**
```bash
python app.py
```

**Option 2: Using Flask CLI**
```bash
flask run --host=0.0.0.0 --port=5503
```

**Option 3: With debug mode (development)**
```bash
export FLASK_ENV=development  # Linux/Mac
set FLASK_ENV=development     # Windows PowerShell
python app.py
```

---

### Step 7: Access the Application

Open your browser and navigate to:
```
http://localhost:5503
```

The application should redirect to the login page.

---

## 🔧 Troubleshooting

### Issue: "JWT_SECRET must be set"
**Solution:** Make sure your `.env` file exists and contains `JWT_SECRET`

### Issue: "FLASK_SECRET_KEY must be set"
**Solution:** Check that `.env` file has `FLASK_SECRET_KEY` set

### Issue: Database connection error
**Solution:**
- Verify MySQL is running: `mysql -u root -p`
- Check database credentials in `.env`
- Ensure database `Erp_Db` exists

### Issue: Port already in use
**Solution:** 
- Change port in `app.py` (line ~1712) or use:
  ```bash
  flask run --port=5001
  ```

### Issue: Email not sending
**Solution:**
- Verify Gmail App-Specific Password is correct
- Check that 2-Step Verification is enabled
- Ensure `MAIL_USERNAME` and `MAIL_PASSWORD` are set correctly

### Issue: Module not found errors
**Solution:**
- Make sure virtual environment is activated
- Install missing packages: `pip install <package_name>`

### Issue: CSRF token errors
**Solution:**
- Make sure templates include CSRF token meta tag
- Check that `csrf_helper.js` is loaded in templates

---

## 📝 Quick Start Commands

**Complete setup in one go:**

```bash
# 1. Activate venv
venv\Scripts\Activate.ps1  # Windows
# or
source venv/bin/activate   # Linux/Mac

# 2. Install dependencies (if needed)
pip install flask mysql-connector-python python-dotenv flask-mail PyJWT itsdangerous

# 3. Create .env file
copy env_template.txt .env  # Windows
# or
cp env_template.txt .env    # Linux/Mac

# 4. Edit .env with your values

# 5. Create directories
mkdir logs uploads

# 6. Run application
python app.py
```

---

## 🌐 Production Deployment

For production:

1. **Set environment:**
   ```env
   FLASK_ENV=production
   ```

2. **Use HTTPS:**
   - Set up SSL certificate
   - Update `BASE_URL` to HTTPS URL
   - Use a reverse proxy (nginx/Apache)

3. **Security:**
   - Use strong, unique secrets
   - Enable firewall
   - Regular backups
   - Monitor logs

4. **Database:**
   - Use connection pooling
   - Regular backups
   - Optimize queries

---

## 📊 Application Structure

```
Project1/
├── app.py                 # Main application file
├── security_utils.py      # Security utilities
├── security_enhanced.py  # Enhanced security features
├── .env                   # Environment variables (create this)
├── logs/                  # Log files (created automatically)
│   ├── audit.log         # Security audit log
│   └── errors.log        # Error log
├── uploads/               # Uploaded files
├── frontend/
│   ├── templates/        # HTML templates
│   └── static/           # CSS, JS, images
└── venv/                 # Virtual environment
```

---

## 🔐 Default Admin Account

**Note:** You'll need to create an admin account through the database or registration flow.

To create admin manually in database:
```sql
USE Erp_Db;
INSERT INTO users (fullname, username, email, password_hash, role, is_verified, is_approved, created_at)
VALUES ('Admin User', 'admin', 'admin@example.com', '<hashed_password>', 'admin', 1, 1, NOW());
```

---

## 📞 Support

If you encounter issues:

1. Check `logs/errors.log` for detailed error messages
2. Check `logs/audit.log` for security events
3. Verify all environment variables are set
4. Ensure MySQL is running and accessible
5. Check that all required directories exist

---

## ✅ Verification Checklist

Before running, verify:

- [ ] Virtual environment activated
- [ ] All dependencies installed
- [ ] `.env` file created and configured
- [ ] MySQL server running
- [ ] Database `Erp_Db` exists
- [ ] `logs/` directory exists (or will be created)
- [ ] `uploads/` directory exists
- [ ] Gmail App-Specific Password configured
- [ ] All secret keys generated and set

---

**You're all set! Run `python app.py` to start your ERP system.** 🚀

