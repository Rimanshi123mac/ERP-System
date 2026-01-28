"""
Enhanced security utilities for the ERP system
Includes CSRF protection, audit logging, and security headers
"""
import os
import logging
import hashlib
import secrets
from functools import wraps
from flask import session, request, jsonify, redirect, url_for, flash, make_response
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================ AUDIT LOGGING ============================================

# Configure audit logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)

# Create audit log file handler
if not os.path.exists('logs'):
    os.makedirs('logs')

audit_handler = logging.FileHandler('logs/audit.log')
audit_handler.setLevel(logging.INFO)
audit_formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - UserID:%(user_id)s - IP:%(ip)s - Action:%(action)s - %(message)s'
)
audit_handler.setFormatter(audit_formatter)
audit_logger.addHandler(audit_handler)

def log_audit_event(action, user_id=None, ip=None, details=None, status="success"):
    """Log security-sensitive events"""
    if not user_id:
        user_id = session.get("user_id", "anonymous")
    if not ip:
        ip = request.remote_addr
    
    extra = {
        'user_id': user_id,
        'ip': ip,
        'action': action
    }
    
    message = f"Status:{status}"
    if details:
        message += f" - Details:{details}"
    
    audit_logger.info(message, extra=extra)

# ============================================ CSRF PROTECTION ============================================

def generate_csrf_token():
    """Generate a CSRF token and store it in session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    if 'csrf_token' not in session:
        return False
    return secrets.compare_digest(session.get('csrf_token', ''), token)

def require_csrf(f):
    """Decorator to require CSRF token for POST/PUT/DELETE requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Get token from header, form or JSON (safe for non-JSON requests)
            json_data = request.get_json(silent=True) or {}
            token = (
                request.headers.get('X-CSRF-Token')
                or request.form.get('csrf_token')
                or json_data.get('csrf_token')
            )
            
            if not token or not validate_csrf_token(token):
                log_audit_event("csrf_validation_failed", details=f"Route: {request.endpoint}")
                if request.is_json:
                    return jsonify({"error": "Invalid or missing CSRF token"}), 403
                flash("Security validation failed. Please refresh the page and try again.", "danger")
                return redirect(request.referrer or url_for('login_page'))
        
        return f(*args, **kwargs)
    return decorated_function

# ============================================ OTP SECURITY ============================================

def hash_otp(otp):
    """Hash OTP before storing in database"""
    # Use SHA256 for OTP hashing (one-way hash)
    return hashlib.sha256(otp.encode()).hexdigest()

def verify_otp_hash(otp, stored_hash):
    """Verify OTP against stored hash"""
    computed_hash = hashlib.sha256(otp.encode()).hexdigest()
    return secrets.compare_digest(computed_hash, stored_hash)

# ============================================ SECURITY HEADERS ============================================

def add_security_headers(response):
    """Add security headers to response"""
    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Allow inline for existing code
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'self';"
    )
    
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # HSTS (only in production with HTTPS)
    if os.getenv("FLASK_ENV") == "production":
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# ============================================ ERROR HANDLING ============================================

def handle_error(error, status_code=500, user_message=None):
    """Handle errors with generic user messages and detailed logging"""
    is_production = os.getenv("FLASK_ENV") == "production"
    
    # Log detailed error for debugging
    error_logger = logging.getLogger('errors')
    error_logger.error(f"Error {status_code}: {str(error)}", exc_info=True)
    
    # Log audit event for security-related errors
    if status_code in [401, 403, 429]:
        log_audit_event("security_error", details=f"Status:{status_code} - {str(error)}", status="failed")
    
    # Return generic message to user in production
    if is_production:
        if status_code == 500:
            user_message = user_message or "An internal error occurred. Please try again later."
        elif status_code == 404:
            user_message = user_message or "The requested resource was not found."
        elif status_code == 403:
            user_message = user_message or "You don't have permission to access this resource."
        elif status_code == 401:
            user_message = user_message or "Authentication required."
        else:
            user_message = user_message or "An error occurred. Please try again."
    else:
        # In development, show more details
        user_message = user_message or str(error)
    
    return jsonify({"error": user_message}), status_code

# ============================================ JWT TOKEN HELPERS ============================================

def set_token_cookie(response, token, max_age=7200):
    """Set JWT token in httpOnly cookie"""
    response.set_cookie(
        'auth_token',
        token,
        max_age=max_age,
        httponly=True,
        secure=os.getenv("FLASK_ENV") == "production",
        samesite='Lax',
        path='/'
    )
    return response

def get_token_from_cookie():
    """Get JWT token from httpOnly cookie"""
    return request.cookies.get('auth_token')

def clear_token_cookie(response):
    """Clear JWT token cookie"""
    response.set_cookie('auth_token', '', max_age=0, httponly=True, path='/')
    return response

# ============================================ BROWSER SESSION MANAGEMENT ============================================

def get_or_create_browser_id(request, response):
    """
    Get browser_id from cookie or create a new one.
    Sets browserId cookie if it doesn't exist.
    Returns the browser_id string.
    """
    browser_id = request.cookies.get('browserId')
    
    if not browser_id:
        # Generate a new secure random UUID for this browser
        browser_id = secrets.token_urlsafe(32)
        # Set cookie with 1 year expiry
        response.set_cookie(
            'browserId',
            browser_id,
            max_age=31536000,  # 1 year in seconds
            httponly=True,
            secure=os.getenv("FLASK_ENV") == "production",
            samesite='Lax',
            path='/'
        )
    
    return browser_id

def get_browser_id_from_request(request):
    """Get browser_id from request cookies without creating a new one"""
    return request.cookies.get('browserId')

def set_browser_id_cookie(response, browser_id):
    """Set browserId cookie"""
    response.set_cookie(
        'browserId',
        browser_id,
        max_age=31536000,  # 1 year
        httponly=True,
        secure=os.getenv("FLASK_ENV") == "production",
        samesite='Lax',
        path='/'
    )
    return response

def clear_browser_id_cookie(response):
    """Clear browserId cookie (optional - usually we keep it)"""
    response.set_cookie('browserId', '', max_age=0, httponly=True, path='/')
    return response

 