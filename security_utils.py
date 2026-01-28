"""
Security utilities for the ERP system
Provides decorators and functions for authentication, authorization, and security
"""
from functools import wraps
from flask import session, request, jsonify, redirect, url_for, flash
import jwt
import os
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import re

# Load JWT secret
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET or JWT_SECRET == "default_secret_key":
    raise ValueError("JWT_SECRET must be set in environment variables and cannot be default_secret_key")

# Rate limiting storage (in production, use Redis)
_rate_limit_store = {}
_rate_limit_window = {}

def require_login(f):
    """Decorator to require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            flash("Please login first", "danger")
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            flash("Please login first", "danger")
            return redirect(url_for("login_page"))
        
        if session.get("role") != "admin":
            if request.is_json:
                return jsonify({"error": "Admin access required"}), 403
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for("login_page"))
        
        return f(*args, **kwargs)
    return decorated_function

def require_role(*allowed_roles):
    """Decorator to require specific role(s)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                if request.is_json:
                    return jsonify({"error": "Authentication required"}), 401
                flash("Please login first", "danger")
                return redirect(url_for("login_page"))
            
            user_role = session.get("role", "").lower()
            if user_role not in [r.lower() for r in allowed_roles]:
                if request.is_json:
                    return jsonify({"error": "Insufficient permissions"}), 403
                flash("Access denied. Insufficient permissions.", "danger")
                return redirect(url_for("login_page"))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def verify_user_owns_resource(user_id_from_url):
    """Verify that the logged-in user owns the resource or is admin"""
    if "user_id" not in session:
        return False
    
    session_user_id = session.get("user_id")
    user_role = session.get("role", "").lower()
    
    # Admin can access any resource
    if user_role == "admin":
        return True
    
    # User can only access their own resource
    return session_user_id == user_id_from_url

def rate_limit(max_requests=5, window_seconds=60, key_func=None):
    """
    Simple rate limiting decorator
    In production, use Flask-Limiter with Redis
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier
            if key_func:
                key = key_func()
            else:
                key = request.remote_addr
            
            now = datetime.now()
            
            # Clean old entries
            if key in _rate_limit_window:
                if now > _rate_limit_window[key] + timedelta(seconds=window_seconds):
                    _rate_limit_store[key] = 0
                    _rate_limit_window[key] = now
            
            # Check rate limit
            if key not in _rate_limit_store:
                _rate_limit_store[key] = 0
                _rate_limit_window[key] = now
            
            if _rate_limit_store[key] >= max_requests:
                return jsonify({
                    "error": "Rate limit exceeded. Please try again later."
                }), 429
            
            _rate_limit_store[key] += 1
            _rate_limit_window[key] = now
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    """Validate username format"""
    if not username or len(username) < 3 or len(username) > 30:
        return False
    # Allow alphanumeric, underscore, hyphen
    pattern = r'^[a-zA-Z0-9_-]+$'
    return re.match(pattern, username) is not None

def validate_password(password):
    """Validate password strength"""
    if not password or len(password) < 8:
        return False
    # At least one uppercase, one lowercase, one digit
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    return has_upper and has_lower and has_digit

def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal"""
    # Use werkzeug's secure_filename
    safe_name = secure_filename(filename)
    
    # Additional checks
    if not safe_name or safe_name.startswith('.'):
        return None
    
    # Prevent path traversal attempts
    if '..' in safe_name or '/' in safe_name or '\\' in safe_name:
        return None
    
    return safe_name

def is_safe_file_type(filename):
    """Check if file type is safe for upload"""
    # Remove dangerous file types
    dangerous_extensions = {'exe', 'msi', 'jar', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js'}
    
    if not filename or '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    return ext not in dangerous_extensions

def validate_jwt_token(token):
    """Validate JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True, payload
    except jwt.ExpiredSignatureError:
        return False, "Token expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"

def get_current_user_id():
    """Get current logged-in user ID safely"""
    return session.get("user_id")

def get_current_user_role():
    """Get current logged-in user role safely"""
    return session.get("role", "").lower()

def check_feature_access_safe(user_id, feature_name):
    """Safely check if user has access to a feature"""
    from app1 import get_db_connection
    
    if not user_id:
        return False
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT is_enabled FROM user_access 
            WHERE user_id=%s AND feature_name=%s
        """, (user_id, feature_name))
        
        row = cursor.fetchone()
        return bool(row and row["is_enabled"])
    except Exception as e:
        print(f"Error checking feature access: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

def sanitize_input(text, max_length=1000):
    """Sanitize user input"""
    if not text:
        return ""
    
    if len(text) > max_length:
        text = text[:max_length]
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    return text.strip()

