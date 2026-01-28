# Database Setup Guide

## Issue: MySQL Access Denied Error

You're getting this error because:
- The `.env` file is missing, OR
- The `DB_PASSWORD` in `.env` is incorrect

## Quick Fix Steps

### Step 1: Find Your MySQL Root Password

If you don't remember your MySQL root password, you have a few options:

**Option A: If you know your password**
- Use that password in the `.env` file

**Option B: Reset MySQL password (if forgotten)**
1. Stop MySQL service
2. Start MySQL in safe mode (varies by OS)
3. Reset the password
4. Restart MySQL service

**Option C: Use a different MySQL user**
- Create a new MySQL user with a password you know
- Use that user in `.env` instead of root

### Step 2: Create .env File

1. Copy the template:
   ```powershell
   copy env_template.txt .env
   ```

2. Open `.env` file in a text editor

3. **IMPORTANT**: Set your MySQL password:
   ```env
   DB_PASSWORD=your_actual_mysql_password_here
   ```

### Step 3: Verify MySQL Connection

Test your MySQL connection manually:

```powershell
mysql -u root -p
```

Enter your password when prompted. If this works, use the same password in `.env`.

### Step 4: Create the Database

If the database doesn't exist, create it:

```sql
CREATE DATABASE Erp_Db;
```

### Step 5: Restart Your Application

After updating `.env`, restart your Flask application.

## Common Issues

### Issue: "Access denied for user 'root'@'localhost'"
**Solution**: 
- Check that `DB_PASSWORD` in `.env` matches your MySQL root password
- Make sure there are no extra spaces in the password
- Try connecting manually: `mysql -u root -p`

### Issue: "Database 'Erp_Db' does not exist"
**Solution**: 
- Create the database: `CREATE DATABASE Erp_Db;`

### Issue: "Cannot connect to MySQL server"
**Solution**: 
- Make sure MySQL service is running
- Check `DB_HOST` in `.env` (should be `localhost`)

## Example .env File

```env
# Flask Configuration
FLASK_SECRET_KEY=your_secret_key_here_minimum_32_characters_long
FLASK_ENV=development
JWT_SECRET=your_jwt_secret_key_here_minimum_32_characters_long

# Database Configuration
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_root_password_here
DB_NAME=Erp_Db

# Email Configuration (Gmail)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_specific_password_here
MAIL_DEFAULT_SENDER=your_email@gmail.com

# Application Configuration
BASE_URL=http://localhost:5503
TEMP_PASSWORD=temporary_password_123

# License Key Configuration
LICENSE_SECRET_KEY=your_license_secret_key_here_minimum_32_characters_long
```

## Generate Secret Keys

Run these commands to generate secure keys:

```powershell
python -c "import secrets; print('FLASK_SECRET_KEY=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('JWT_SECRET=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('LICENSE_SECRET_KEY=' + secrets.token_urlsafe(32))"
```

Copy the output and paste into your `.env` file.

