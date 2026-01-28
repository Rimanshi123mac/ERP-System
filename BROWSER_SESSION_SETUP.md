# Browser Session Management Setup Guide

This guide explains how to set up and use the browser-based session management system that prevents multiple users from logging in on the same browser.

## Features

✅ **Cookie Validation** - All session cookies are validated on every request  
✅ **One User Per Browser** - Only one user can be logged in per browser at a time  
✅ **Multi-Browser Support** - Users can log in from multiple browsers/devices  
✅ **Automatic Cleanup** - Expired sessions are automatically cleaned up  

## Setup Instructions

### Step 1: Create the Database Table

Run the setup script to create the `browser_sessions` table:

```bash
python setup_browser_sessions.py
```

Or manually run the SQL:

```sql
CREATE TABLE IF NOT EXISTS browser_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    browser_id VARCHAR(255) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    session_token TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    INDEX idx_browser_id (browser_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

### Step 2: Restart Your Application

After creating the table, restart your Flask application:

```bash
python app.py
```

## How It Works

### Browser Identification

1. **browserId Cookie**: A unique identifier is generated for each browser and stored in a long-lived cookie (1 year expiry)
2. **Session Tracking**: The system tracks which user is logged in for each `browser_id` in the `browser_sessions` table

### Login Flow

1. User attempts to log in
2. System checks if there's an existing session for that `browser_id`
3. **If different user exists**: Login is blocked with error message
4. **If same user or no session**: Login proceeds and browser session is created/updated

### Cookie Validation

On every request:
1. JWT token is validated from cookie
2. Browser session is checked against the token
3. If mismatch detected, token is cleared and user is logged out
4. Last active time is updated

### Logout

When user logs out:
1. Browser session is deleted from database
2. Session cookie is cleared
3. BrowserId cookie is kept (for next login)

## User Experience

### Scenario 1: First Login
- User logs in → Session created → Access granted ✅

### Scenario 2: Same User, Same Browser
- User logs in again → Session updated → Access granted ✅

### Scenario 3: Different User, Same Browser
- User A is logged in
- User B tries to log in → **BLOCKED** ❌
- Error message: "Another user is already logged in on this browser. Please log out first before logging in with a different account."

### Scenario 4: Same User, Different Browser
- User logs in from Chrome → Session 1 created ✅
- User logs in from Firefox → Session 2 created ✅
- Both sessions work independently ✅

## API Response

When login is blocked due to existing user:

```json
{
    "error": "Another user is already logged in on this browser. Please log out first before logging in with a different account."
}
```

HTTP Status: `409 Conflict`

## Security Features

1. **Cookie Tampering Detection**: If token doesn't match browser session, it's detected and cleared
2. **Token Validation**: JWT tokens are validated on every request
3. **Session Expiry**: Sessions expire after 2 hours (configurable)
4. **Audit Logging**: All security events are logged

## Maintenance

### Cleanup Expired Sessions

You can periodically clean up expired sessions by calling:

```python
from app import cleanup_expired_sessions
cleanup_expired_sessions()
```

Or set up a cron job to run this periodically.

## Troubleshooting

### Issue: "Table browser_sessions doesn't exist"
**Solution**: Run `python setup_browser_sessions.py`

### Issue: Multiple users can still log in
**Solution**: 
1. Check that the table was created correctly
2. Verify middleware is running (check logs)
3. Ensure browserId cookie is being set

### Issue: Users getting logged out unexpectedly
**Solution**: 
1. Check token expiry settings
2. Verify JWT_SECRET is set correctly
3. Check browser session expiry times

## Testing

To test the implementation:

1. **Test Single User Per Browser**:
   - Log in as User A in Chrome
   - Try to log in as User B in Chrome → Should be blocked

2. **Test Multi-Browser**:
   - Log in as User A in Chrome → Should work
   - Log in as User A in Firefox → Should work

3. **Test Cookie Validation**:
   - Log in normally
   - Manually modify the auth_token cookie
   - Make a request → Should be logged out

## Files Modified

- `app.py` - Added browser session management and login validation
- `security_enhanced.py` - Added browserId cookie management functions
- `create_browser_sessions_table.sql` - SQL script for table creation
- `setup_browser_sessions.py` - Python script to create table

