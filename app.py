from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, send_from_directory, make_response
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from dotenv import load_dotenv
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from random import randint
from datetime import datetime, timedelta, time
import shutil
from security_utils import require_login, require_admin, require_role, verify_user_owns_resource, rate_limit, validate_email, validate_username, validate_password, sanitize_input
from security_enhanced import (
    generate_csrf_token, require_csrf, hash_otp, verify_otp_hash,
    add_security_headers, log_audit_event, handle_error,
    set_token_cookie, get_token_from_cookie, clear_token_cookie,
    get_or_create_browser_id, get_browser_id_from_request
)
import logging

from datetime import datetime
from captcha.image import ImageCaptcha
import random, string
from flask import session, send_file
from io import BytesIO


# =================================================== CONFIG ====================================================
load_dotenv()

#  JWT_SECRET 
secret = os.getenv("JWT_SECRET")
if not secret or secret == "default_secret_key":
    raise ValueError("JWT_SECRET must be set in environment variables and cannot be 'default_secret_key'")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "frontend", "templates"),
    static_folder=os.path.join(BASE_DIR, "frontend", "static")
)



# =============================================logs ============================================

def log_action(user_id, username, role, action, details=""):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO logs (user_id, username, role, action, details)
                    VALUES (%s, %s, %s, %s, %s)
                """, (user_id, username, role, action, details))
                conn.commit()
    except Exception as e:
        print("Logging failed:", e)


# ==============================================================================================================================

@app.context_processor
def inject_now():
    return {"now": datetime.now}
BASE_URL = os.getenv("BASE_URL", "https://colonisable-untongued-holden.ngrok-free.dev")

app.secret_key = os.getenv("FLASK_SECRET_KEY")
if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY must be set in environment variables")
app.config['SESSION_TYPE'] = 'filesystem'   # For flash msg
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.getenv("FLASK_ENV") == "production"  # HTTPS only in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session timeout

temp_password = generate_password_hash(os.getenv("TEMP_PASSWORD", "temporary_password"))

# ============================================ SECURITY HEADERS ============================================
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    return add_security_headers(response)

# ============================================ BROWSER ID MIDDLEWARE ============================================
@app.before_request
def manage_browser_id():
    """Generate or retrieve browserId cookie for every request"""
    browser_id = get_browser_id_from_request(request)
    if not browser_id:
        import secrets
        browser_id = secrets.token_urlsafe(32)
    request.browser_id = browser_id


# ===================================== CAPTCHA ROUTE =====================================================
@app.route("/captcha")
def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    session["captcha"] = captcha_text

    image = ImageCaptcha()
    data = image.generate(captcha_text)

    return send_file(data, mimetype="image/png")


# ============================================ COOKIE VALIDATION MIDDLEWARE ============================================
@app.before_request
def validate_session_cookie():
    """
    Validate JWT token from cookie and browser session on each request.
    This ensures cookies are valid and not tampered with.
    """

    if request.endpoint in ['login_page', 'register_page', 'static', 'send_verification_email', 
                           'verify_email', 'send_otp', 'verify_otp', 'home', 'login', 'register_api']:
        return
    
    token = get_token_from_cookie()
    
    if token:
        from security_utils import validate_jwt_token
        is_valid, payload = validate_jwt_token(token)
        
        if not is_valid:
            request.invalid_token = True
            if "user_id" in session:
                session.clear()
            return
        
        browser_id = getattr(request, 'browser_id', None)
        if browser_id:
            browser_session = get_browser_session(browser_id)
            if browser_session:
                if browser_session["session_token"] != token:
                    log_audit_event("cookie_tampering_detected", user_id=payload.get("id"), 
                                   details="Token mismatch with browser session", status="security_alert")
                    request.invalid_token = True
                    if "user_id" in session:
                        session.clear()
                    return
                
                if browser_session["user_id"] != payload.get("id"):
                    log_audit_event("cookie_tampering_detected", user_id=payload.get("id"), 
                                   details="User ID mismatch with browser session", status="security_alert")
                    request.invalid_token = True
                    if "user_id" in session:
                        session.clear()
                    return
                
                update_browser_session(browser_id, browser_session["user_id"], token, browser_session["expires_at"])
            else:
                request.invalid_token = True
                if "user_id" in session:
                    session.clear()
                return

@app.after_request
def set_browser_id_cookie(response):
    """Ensure browserId cookie is set in response"""
    browser_id = getattr(request, 'browser_id', None)
    if browser_id:
        existing_browser_id = request.cookies.get('browserId')
        if not existing_browser_id:
            from security_enhanced import set_browser_id_cookie as set_cookie
            response = set_cookie(response, browser_id)
    
    if hasattr(request, 'invalid_token') and request.invalid_token:
        response = clear_token_cookie(response)
    
    return response

# ============================================ ERROR HANDLING ============================================

error_logger = logging.getLogger('errors')
error_logger.setLevel(logging.ERROR)
if not os.path.exists('logs'):
    os.makedirs('logs')
error_handler = logging.FileHandler('logs/errors.log')
error_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
error_logger.addHandler(error_handler)

@app.errorhandler(404)
def not_found(error):
    return handle_error(error, 404, "The requested resource was not found.")

@app.errorhandler(500)
def internal_error(error):
    return handle_error(error, 500, "An internal error occurred. Please try again later.")

@app.errorhandler(403)
def forbidden(error):
    return handle_error(error, 403, "You don't have permission to access this resource.")

@app.errorhandler(401)
def unauthorized(error):
    return handle_error(error, 401, "Authentication required.")


# =============================================== MAIL CONFIGURATION ============================================

app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", "587"))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")

mail = Mail(app)

# ---------------------------- Email verification token serializer -------------------
s = URLSafeTimedSerializer(app.secret_key)

def generate_verification_token(email):
    return s.dumps(email, salt="email-verify")

def confirm_verification_token(token, expiration=3600):
    try:
        email = s.loads(token, salt="email-verify", max_age=expiration)
    except Exception:
        return None
    return email


# ============================================= FILE UPLOAD =====================================================
upload_folder = "uploads"
sample_folder = os.path.join(upload_folder, "sample")

allowed_extensions = {"txt", "pdf", "doc", "docx", "rtf", "exe", "jar", "msi",
                       "png", "jpg", "jpeg", "svg", "gif", "mp3", "mp4",
                       "zip", "rar", "tar", 
                       "lib","csv",
                       "py", "java", "js", "html", "css", "c", "cpp", "php", "sql"
                    }
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit

app.config["upload_folder"] = upload_folder
app.config["sample_folder"] = sample_folder

os.makedirs(upload_folder, exist_ok=True)
os.makedirs(sample_folder, exist_ok=True)
files = []

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ================================================== DB CONNECTION ===========================================
def get_db_connection():
    db_host = os.getenv("DB_HOST", "localhost")
    db_user = os.getenv("DB_USER", "root")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME", "Erp_Db")
    
    if not db_password:
        raise ValueError(
            "DB_PASSWORD is not set in environment variables. "
            "Please create a .env file with your database password."
        )
    
    try:
        connection = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name
        )
        return connection
    except mysql.connector.Error as err:
        error_msg = str(err)
        if err.errno == 1045:
            raise ValueError(
                f"MySQL Access Denied: Invalid password for user '{db_user}'@'{db_host}'. "
                f"Please check your DB_PASSWORD in the .env file. "
                f"Error: {error_msg}"
            )
        elif err.errno == 1049:
            raise ValueError(
                f"Database '{db_name}' does not exist. "
                f"Please create it first: CREATE DATABASE {db_name};"
            )
        elif err.errno == 2003:
            raise ValueError(
                f"Cannot connect to MySQL server at '{db_host}'. "
                f"Please ensure MySQL is running."
            )
        else:
            raise ValueError(f"Database connection error: {error_msg}")


def get_db_cursor(conn):
    return conn.cursor(dictionary=True, buffered=True)


# ============================================ BROWSER SESSION MANAGEMENT ============================================
def get_browser_session(browser_id):
    """Get existing browser session from database"""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT * FROM browser_sessions 
            WHERE browser_id = %s AND expires_at > NOW()
        """, (browser_id,))
        session_data = cursor.fetchone()
        return session_data
    finally:
        cursor.close()
        connection.close()

def create_browser_session(browser_id, user_id, session_token, expires_at):
    """Create a new browser session in database"""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("""
            INSERT INTO browser_sessions (browser_id, user_id, session_token, expires_at)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                user_id = VALUES(user_id),
                session_token = VALUES(session_token),
                expires_at = VALUES(expires_at),
                last_active_at = NOW()
        """, (browser_id, user_id, session_token, expires_at))
        connection.commit()
    finally:
        cursor.close()
        connection.close()

def update_browser_session(browser_id, user_id, session_token, expires_at):
    """Update existing browser session"""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("""
            UPDATE browser_sessions 
            SET user_id = %s, session_token = %s, expires_at = %s, last_active_at = NOW()
            WHERE browser_id = %s
        """, (user_id, session_token, expires_at, browser_id))
        connection.commit()
    finally:
        cursor.close()
        connection.close()

def delete_browser_session(browser_id):
    """Delete browser session from database"""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM browser_sessions WHERE browser_id = %s", (browser_id,))
        connection.commit()
    finally:
        cursor.close()
        connection.close()

def cleanup_expired_sessions():
    """Clean up expired browser sessions (can be called periodically)"""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("DELETE FROM browser_sessions WHERE expires_at < NOW()")
        connection.commit()
    finally:
        cursor.close()
        connection.close()


# ==================================================== LICENSE KEY ===========================================
secret1 = os.getenv("LICENSE_SECRET_KEY")
if not secret1:
    raise ValueError("LICENSE_SECRET_KEY must be set in environment variables")

def validate_license(token):
    try:
        payload = jwt.decode(token, secret1, algorithms=["HS256"])
        return True, payload
    except ExpiredSignatureError:
        return False, "License expired"
    except InvalidTokenError:
        return False, "Invalid license"

from functools import wraps
from flask import request, jsonify

def require_license(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-License-Token")
        if not token:
            return jsonify({"error": "License key required"}), 401
        ok, info = validate_license(token)
        if not ok:
            return jsonify({"error": "Invalid or expired license", "details": info}), 403
        return fn(*args, **kwargs)
    return wrapper


# ===================================================== ROUTES =====================================================
@app.route("/")
def home():
    return redirect(url_for("login_page"))


# =================================================== REGISTER ======================================================= 
@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")

@app.route("/api/register", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=300)  # 5 requests per 5 minutes
@require_csrf
def register_api():
    data = request.get_json()
    fullname = sanitize_input(data.get("fullname"), max_length=100)
    username = sanitize_input(data.get("username"), max_length=30)
    email = data.get("email", "").strip().lower()
    password = data.get("password")

    if not fullname or not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400
    
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not validate_username(username):
        return jsonify({"error": "Invalid username. Must be 3-30 characters, alphanumeric with _ or -"}), 400
    if not validate_password(password):
        return jsonify({"error": "Password must be at least 8 characters with uppercase, lowercase, and digit"}), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    existing_user = cursor.fetchone()

    if not existing_user:
        return jsonify({"error": "Please verify your email first."}), 403
    if existing_user["is_verified"] == 0:
        return jsonify({"error": "Email not verified. Please check your inbox."}), 403

    try:
        hashed_password = generate_password_hash(password)
        cursor.execute("""
            UPDATE users
            SET username=%s, password_hash=%s, is_approved=0
            WHERE email=%s
        """, (username, hashed_password, email))
        connection.commit()
        
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        
        log_audit_event("user_registration", user_id=user["id"] if user else None, details=f"Email: {email}, Username: {username}")

        return jsonify({"message": "Registration complete! Wait for admin approval."}), 201
    except Exception as e:
        connection.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        connection.close()

@app.route("/api/create-account", methods=["POST"])
def create_account():
    email = request.json.get("email").strip().lower()
    
    # 1. Prevent duplicates
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if user:
        return jsonify({"error": "Email already exists"}), 400

    # 2. Generate token
    token = generate_verification_token(email)

    # 3. Insert user with only email + token
    cursor.execute("""
        INSERT INTO users (email, is_verified, is_approved, verification_token)
        VALUES (%s, 0, 0, %s)
    """, (email, token))
    connection.commit()

    # 4. Send verification mail
    send_verification_email(email, token)

    return jsonify({"message": "Verification email sent!"}), 200


# ---------------------------------- Verify Email API --------------------------
@app.route("/api/send_verification", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=300)  # 5 requests per 5 minutes
def send_verification_email():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    fullname = sanitize_input(data.get("fullname"), max_length=100)

    if not email or not fullname:
        return jsonify({"error": "Email and fullname are required"}), 400
    
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing_user = cursor.fetchone()

        temp_password = generate_password_hash("Temp@123")

        if existing_user:
            if existing_user["is_verified"] == 1:
                return jsonify({"message": "Email already verified. Please proceed to login."}), 200
            
            
            token = existing_user.get("verification_token")
            if not token:
                token = generate_verification_token(email)
                cursor.execute(
                    "UPDATE users SET verification_token=%s WHERE email=%s",
                    (token, email)
                )
                connection.commit()

        else:
            token = generate_verification_token(email)

            cursor.execute("""
                INSERT INTO users(fullname, username, email, password_hash, verification_token, is_verified, is_approved, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (fullname, "", email, temp_password, token, 0, 0, datetime.now()))
            connection.commit()

        NGROK_BASE = "https://colonisable-untongued-holden.ngrok-free.dev"

        verify_url = f"{NGROK_BASE}/verify/{token}"

        msg = Message("Verify Your Email - NishGrid", recipients=[email])
        msg.body = f"""
Hi {fullname},

Please verify your email by clicking the link below:
{verify_url}

This link will expire in 1 hour.

Regards,
NishGrid Team
"""
        mail.send(msg)

        return jsonify({"message": "Verification email sent successfully!"}), 200

    except Exception as e:
        connection.rollback()
        print("Mail error:", str(e))
        return jsonify({"error": "Failed to send verification email"}), 500

    finally:
        cursor.close()
        connection.close()


# ------------------------------------ Email Verification ----------------------
@app.route("/verify/<token>")
def verify_email(token):
    try:
        email = confirm_verification_token(token)
        if not email:
            return render_template("message.html", 
                                   title="Invalid Link", 
                                   message="Verification link is invalid or expired.")

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("UPDATE users SET is_verified = 1 WHERE email = %s", (email,))
        connection.commit()

        cursor.execute("SELECT fullname FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        return render_template("message.html", 
                               title="Email Verified!", 
                               message=f"Hi {user[0]}, your email has been verified successfully! You can now go to the login page.")
    except Exception as e:
        print("Verification error:", str(e))
        return render_template("message.html", 
                               title="Verification Failed", 
                               message="Something went wrong while verifying your email. Please try again later.")
    finally:
        print("Verify route triggered")


# ================================= Apperance emp ======================================
@app.route("/api/save-appearance", methods=["POST"])
@require_login
def save_appearance():
    data = request.get_json()
    user_id = session["user_id"]

    theme = data.get("theme", "light")
    font_family = data.get("font_family", "Poppins")
    font_size = data.get("font_size", "16px")
    is_bold = 1 if data.get("is_bold") else 0

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO user_preferences (user_id, theme, font_family, font_size, is_bold)
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            theme=%s,
            font_family=%s,
            font_size=%s,
            is_bold=%s
    """, (
        user_id, theme, font_family, font_size, is_bold,
        theme, font_family, font_size, is_bold
    ))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "success"})

def get_user_appearance(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT theme, font_family, font_size, is_bold "
        "FROM user_preferences WHERE user_id=%s",
        (user_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        # defaults match your table defaults
        row = {
            "theme": "light",
            "font_family": "Poppins",
            "font_size": "16px",
            "is_bold": 0
        }
    return row


@app.context_processor
def inject_user_prefs():
    if 'user_id' not in session:
        default_prefs = {'theme': 'light', 'font_family': 'Poppins', 'font_size': '16px', 'is_bold': 0}
        return {'user_prefs': default_prefs, 'client_prefs': {}}
    
    role = session.get("role")
    user_id = session.get("user_id")
    default_prefs = {'theme': 'light', 'font_family': 'Poppins', 'font_size': '16px', 'is_bold': 0}
    
    try:
        if role == "employee" or role == "admin":
            prefs = get_user_appearance(user_id) or default_prefs
            return {'user_prefs': prefs, 'client_prefs': {}}
        
        if role == "client":
            return {'user_prefs': {}, 'client_prefs': get_client_prefs()}
    
    except Exception as e:
        print(f"Context processor error: {e}")
        return {'user_prefs': default_prefs, 'client_prefs': {}}
    
    return {'user_prefs': default_prefs, 'client_prefs': {}}

# ----------------------------------------- FOR ADMIN -----------------------
def get_admin_prefs():
    user_id = session.get('user_id')
    if not user_id:
        return {}
    return get_user_appearance(user_id)  

# ----------------------------------------Client thme--------------------------------
def get_client_prefs():
    user_id = session.get("user_id")
    if not user_id:
        return {}

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT theme FROM customers WHERE owner_id=%s", (user_id,))
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row or not row.get("theme"):
        return {"theme": "default"}

    return {"theme": row["theme"]}


# ===========================================================================

@app.after_request
def apply_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com data:;"
    return response



# ===================================================== LOGIN =====================================================
def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


@app.route("/api/send_otp", methods=["POST"])
@rate_limit(max_requests=5, window_seconds=300)  # 5 requests per 5 minutes
def send_otp():
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username required"}), 400

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if user["is_verified"] == 1 or user["role"] == "admin":
        return jsonify({"message": "Already verified, login directly."}), 200

    # Generate 6-digit OTP
    otp = str(randint(100000, 999999))
    expiry = datetime.now() + timedelta(minutes=15)
    
    # SECURITY: Hash OTP before storing
    otp_hash = hash_otp(otp)

    cursor.execute("UPDATE users SET otp_code=%s, otp_expiry=%s WHERE id=%s",
                   (otp_hash, expiry, user["id"]))
    connection.commit()
    
    # Log OTP generation
    log_audit_event("otp_generated", user_id=user["id"], details=f"Username: {username}")

    msg = Message("Your Login OTP - NishGrid", recipients=[user["email"]])
    msg.body = f"""
    Hello {user['fullname']},

    Your OTP for login is: {otp}
    This OTP is valid for 15 minutes.

    Regards,
    NishGrid Security Team
    """
    mail.send(msg)

    cursor.close()
    connection.close()

    return jsonify({"message": "OTP sent to your registered email."}), 200

@app.route("/api/verify_otp", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=300)  # 10 attempts per 5 minutes
def verify_otp():
    data = request.get_json()
    username = data.get("username")
    otp = data.get("otp")

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if user["role"] == "admin":
        return jsonify({"message": "Admin does not require OTP"}), 200

    if user["is_verified"] == 1:
        return jsonify({"message": "Already verified"}), 200
    
    if not user["otp_code"]:
        log_audit_event("otp_verification_failed", user_id=user["id"], details="OTP not sent/generated", status="failed")
        return jsonify({"error": "OTP not sent/generated"}), 400

    # SECURITY: Verify OTP using hash comparison
    if not verify_otp_hash(otp, user["otp_code"]):
        log_audit_event("otp_verification_failed", user_id=user["id"], details="Invalid OTP", status="failed")
        return jsonify({"error": "Invalid OTP"}), 401

    if datetime.now() > user["otp_expiry"]:
        log_audit_event("otp_verification_failed", user_id=user["id"], details="OTP expired", status="failed")
        return jsonify({"error": "OTP expired"}), 401

    # Clear OTP after success
    cursor.execute("UPDATE users SET is_verified=1, otp_code=NULL, otp_expiry=NULL WHERE id=%s", (user["id"],))
    connection.commit()
    
    # Log successful OTP verification
    log_audit_event("otp_verified", user_id=user["id"], details=f"Username: {username}")

    # You can now generate a JWT token or session here
    '''token = jwt.encode(
        {"id": user["id"], "username": user["username"], "role": user["role"]},
        secret,
        algorithm="HS256"
    )'''

    cursor.close()
    connection.close()

    return jsonify({"message": "OTP verified successfully!" }), 200

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")
 

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request data"}), 400

        username = data.get("username")
        password = data.get("password")
        captcha_input = data.get("captcha")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        if not captcha_input:
            return jsonify({"error": "CAPTCHA is required"}), 400

        # ---------- CAPTCHA CHECK ----------
        stored_captcha = session.get("captcha")
        if not stored_captcha or captcha_input.lower() != stored_captcha.lower():
            return jsonify({"error": "Invalid CAPTCHA"}), 400

        # ---------- USER FETCH ----------
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if not user or not user.get("password_hash"):
            return jsonify({"error": "Invalid username or password"}), 401

        if not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "Invalid username or password"}), 401

        # ---------- VERIFICATION ----------
        if user["is_verified"] == 0:
            return jsonify({"status": "unverified"}), 403

        if user["is_approved"] == 0:
            return jsonify({"status": "pending"}), 202

        if user["is_approved"] == 2:
            return jsonify({"status": "rejected"}), 403

        role = user["role"]
        if role not in ["admin", "client", "employee"]:
            return jsonify({"error": "Invalid role"}), 403

        # ---------- PREVENT MULTI-LOGIN ----------
        browser_id = getattr(request, "browser_id", None)
        if not browser_id:
            browser_id = get_browser_id_from_request(request)

        if browser_id:
            existing = get_browser_session(browser_id)
            if existing and existing["user_id"] != user["id"]:
                return jsonify({"error": "Another user is already logged in on this browser"}), 409

        # ---------- CLEAR & SET SESSION ----------
        session.clear()
        session["user_id"] = user["id"]
        session["role"] = role
        session["username"] = user["username"]
        session["fullname"] = user["fullname"]
        session.permanent = True

        if role == "employee":
            session["employee_name"] = user["fullname"]   
            user_theme = user.get("theme", "default")
            session["theme"] = user_theme

        if role == "client":
            cursor.execute("SELECT theme FROM customers WHERE owner_id=%s", (user["id"],))
            customer = cursor.fetchone()
            if customer and customer.get("theme"):
                session["theme"] = customer["theme"]
            else:
                session["theme"] = "default"


        # ---------- JWT TOKEN ----------
        token = jwt.encode(
            {"id": user["id"], "username": user["username"], "role": role},
            secret,
            algorithm="HS256"
        )

        if browser_id:
            expires_at = datetime.now() + timedelta(hours=2)
            create_browser_session(browser_id, user["id"], token, expires_at)

        # ---------- LOG ----------
        log_action(
            user_id=user["id"],
            username=user["username"],
            role=role,
            action="login_success",
            details=f"{role} logged in"
        )

        response = jsonify({
            "status": "approved",
            "role": role
        })
        response = set_token_cookie(response, token)
        return response, 200

    except Exception as e:
        print("Login error:", e)
        return jsonify({"error": "Server error"}), 500


# ================================================ Dashboard =====================================================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please login first.")
        return redirect(url_for("login_page"))
    return f"Welcome {session['username']}! This is your dashboard."

# ================================================ Logout ========================================================
@app.route("/logout")
@require_login
def logout():
    user_id = session.get("user_id")
    username = session.get("username")

    # Log logout BEFORE clearing session
    if user_id:
        log_action(
            user_id=user_id,
            username=username,
            role=session.get("role"),
            action="logout",
            details="User logged out"
        )

    # Get browser_id and delete browser session
    browser_id = getattr(request, 'browser_id', None)
    if not browser_id:
        browser_id = get_browser_id_from_request(request)

    if browser_id:
        delete_browser_session(browser_id)

    session.clear()
    flash("You have been logged out")

    response = redirect(url_for("login_page"))
    response = clear_token_cookie(response)
    return response


# ============================================= Change PAssword ===============================================
@app.route("/api/change_password", methods=["POST"])
@require_login
def change_password():
    data = request.get_json()

    current_password = data.get("current_password")
    new_password = data.get("new_password")

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT password_hash FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    if not check_password_hash(user["password_hash"], current_password):
        return jsonify({"error": "Current password is incorrect"}), 400

    new_hash = generate_password_hash(new_password)

    cursor.execute(
        "UPDATE users SET password_hash=%s WHERE id=%s",
        (new_hash, user_id)
    )

    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Password updated successfully"})




# ********************************************************* ROLE BASED PAGES **********************************************************

# ============================================= ADMIN DASHBOARD ========================================================
@app.route("/admin-alias")
@require_login
@require_admin
def admin():
    return redirect(url_for("admin_dashboard"))


@app.route("/admin")
@require_login
@require_admin
def admin_dashboard():

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ---------------------------------------------------------------------------------
    cursor.execute("SELECT COUNT(*) AS total_users FROM users WHERE is_approved = 1")
    total_users = cursor.fetchone()["total_users"]

    # ------------------------------------------------------------------------------------------------
    cursor.execute("SELECT COUNT(*) AS pending FROM users WHERE is_verified = 1 AND is_approved = 0")
    pending_approvals = cursor.fetchone()["pending"]

    # ------------------------------------------------------------------------------------------------
    cursor.execute("SELECT COUNT(*) AS total_files FROM files WHERE status = 'Active'")
    total_files = cursor.fetchone()["total_files"]

    cursor.close()
    conn.close()

    return render_template(
        "admin.html",
        total_users=total_users,
        pending_approvals=pending_approvals,
        total_files=total_files
    )


# --------------------------- ADMIN PROFILE ----------------------------------------------------
@app.route("/admin/profile")
@require_login
@require_admin
def admin_profile():
    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT fullname, username, email FROM users WHERE id=%s", (user_id,))
    admin_data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    user_prefs = get_admin_prefs()
    return render_template(
        "admin_profile.html", 
        user_prefs=user_prefs,
        admin_fullname=admin_data.get("fullname") if admin_data else session.get("admin_name", ""),
        admin_username=admin_data.get("username") if admin_data else session.get("username", ""),
        admin_email=admin_data.get("email") if admin_data else session.get("admin_email", "")
    )


# -----------------------------------------------------------------------------------
@app.route("/api/pending_users", methods=["GET"])
@require_login
@require_admin
def pending_users():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT id, fullname, username, email, role, created_at FROM users WHERE is_verified =1 and is_approved=0")
    users = cursor.fetchall()
    cursor.close()
    connection.close()
    return jsonify(users)


@app.route("/admin/user/<int:user_id>")
@require_login
@require_admin
def admin_user_profile(user_id):

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ----------------------------------- USER INFO ------------------
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    # ----------------------------------- USER FEATURES ------------------
    cursor.execute("""
        SELECT feature_name, is_enabled 
        FROM user_access 
        WHERE user_id = %s
    """, (user_id,))
    rows = cursor.fetchall()

    features = {row["feature_name"]: bool(row["is_enabled"]) for row in rows}
    
    if user["role"] == "client":
        all_features = ["file_upload", "view_meetings", "dashboard", "client_app", "raise_ticket"]
    elif user["role"] == "employee":
        all_features = ["file_upload", "view_meetings", "dashboard", "core_data", "raise_ticket"]
    else:
        all_features = ["file_upload", "view_meetings", "raise_ticket", "dashboard"]
    
    for f in all_features:
        if f not in features:
            features[f] = False

    # ---------------- ROLE BASED FILE PERMISSION ----------------
    cursor.execute("""
        SELECT can_download, can_upload, can_delete
        FROM permissions
        WHERE role=%s
    """, (user["role"],))
    file_perm = cursor.fetchone()

    # ------------------------------------- FILE ACCESS ----------------
    cursor.execute("SELECT filename FROM files")
    all_files = cursor.fetchall()

    cursor.execute("SELECT filename FROM user_file_access WHERE user_id=%s", (user_id,))
    user_files = cursor.fetchall()
    user_has_file = {f["filename"] for f in user_files}

    # ---------------- CLIENT APPS LIST ----------------
    cursor.execute("SELECT * FROM client_apps ORDER BY created_at DESC")
    apps = cursor.fetchall()

    # ---------------- CLIENT APP PERMISSIONS ----------------
    cursor.execute("SELECT app_id FROM client_app_permissions WHERE client_id=%s", (user_id,))
    permitted = cursor.fetchall()

    permitted_app_ids = {row["app_id"] for row in permitted}

    # ---------------- EMPLOYEE CLIENT ASSIGNMENTS (FOR EMPLOYEES) ----------------
    assigned_clients = []
    if user["role"] == "employee":
        cursor.execute("""
            SELECT ec.client_username, u.fullname, u.email
            FROM employee_clients ec
            JOIN users u ON u.username = ec.client_username
            WHERE ec.employee_username = %s
        """, (user["username"],))
        assigned_clients = cursor.fetchall()

    # ---------------- ALL CLIENTS LIST (FOR ASSIGNING TO EMPLOYEES) ----------------
    all_clients_list = []
    if user["role"] == "employee":
        cursor.execute("SELECT id, username, fullname, email FROM users WHERE role='client' AND is_active=1")
        all_clients_list = cursor.fetchall()

    cursor.close()
    conn.close()

    csrf_token = generate_csrf_token()
    
    return render_template(
        "admin_user_profile_view.html",
        user=user,
        features=features,
        file_perm=file_perm,
        all_files=all_files,
        user_has_file=user_has_file,
        apps=apps,
        permitted_app_ids=permitted_app_ids,
        assigned_clients=assigned_clients,
        all_clients_list=all_clients_list,
        csrf_token=csrf_token
    )



@app.route("/api/toggle_user_access/<int:user_id>", methods=["POST"])
@require_login
@require_admin
def toggle_user_access(user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT access_granted FROM permission WHERE user_id = %s", (user_id,))
        permission = cursor.fetchone()

        if permission:
            new_access = 0 if permission["access_granted"] else 1
            cursor.execute(
                "UPDATE permission SET access_granted = %s WHERE user_id = %s",
                (new_access, user_id)
            )
        else:
            new_access = 1
            cursor.execute(
                "INSERT INTO permission (user_id, access_granted) VALUES (%s, %s)",
                (user_id, new_access)
            )

        connection.commit()
        cursor.close()
        connection.close()

        message = "Access enabled" if new_access else "Access disabled"
        return jsonify({"message": message, "new_access": new_access})

    except Exception as e:
        print("Error toggling user access:", e)
        return jsonify({"error": str(e)}), 500



# ---------------------- Admin Selcet User Role -----------------------------
@app.route("/admin/user/<int:user_id>/update", methods=["POST"])
@require_login
@require_admin
def update_user_role(user_id):
    role = request.form.get("role")

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET role=%s, is_approved=1 WHERE id=%s", (role, user_id))
    connection.commit()
    cursor.close()
    connection.close()

    flash("User approved and role assigned successfully!", "success")
    return redirect(url_for("admin_dashboard")) 

# ---------------------------------------------------------------------------
@app.route("/api/approve_user/<int:user_id>", methods=["POST"])
@require_login
@require_admin
@require_csrf
def approve_user(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("UPDATE users SET is_approved = 1 WHERE id = %s", (user_id,))
        connection.commit()
        
        log_audit_event("user_approved", user_id=session.get("user_id"), details=f"Approved user ID: {user_id}")
        
        return jsonify({"message": "User approved successfully"})
    except Exception as e:
        connection.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# ----------------------------------------------------------------------------
@app.route("/api/reject_user/<int:user_id>", methods=["POST"])
@require_login
@require_admin
@require_csrf
def reject_user(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT username, email FROM users WHERE id = %s", (user_id,))
        user_info = cursor.fetchone()
        
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        connection.commit()
        
        log_audit_event("user_rejected", user_id=session.get("user_id"), 
                       details=f"Rejected user ID: {user_id}, Username: {user_info.get('username') if user_info else 'N/A'}")
        
        return jsonify({"message": "User rejected and deleted successfully"})
    except Exception as e:
        connection.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        connection.close()

# ----------------------------- 2. FILE UPLOAD/DOWNLOAD/DELETE -------------------------------
@app.route("/admin/file-upload")
@require_login
@require_admin
def admin_file_upload_page():
    user_id = session.get("user_id")
    username = session.get("username")

    log_action(
        user_id=user_id,
        username=username,
        role=session.get("role"),
        action="view_file_upload_page",
        details="Admin opened file upload page"
    )

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    perm = {"can_upload": True, "can_download": True, "can_delete": True}

    cursor.execute("SELECT * FROM files WHERE status = 'Active' ORDER BY uploaded_at DESC")
    files = cursor.fetchall()

    cursor.close()
    connection.close()

    csrf_token = generate_csrf_token()
    return render_template("admin-2-fileUpload.html", files=files, perm=perm, csrf_token=csrf_token)


@app.route("/backend/uploads", methods=["GET", "POST"])
@require_login
@require_admin
@require_csrf
def admin_upload():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if request.method == "POST":
        file = request.files.get("file")
        desc = sanitize_input(request.form.get("desc", ""), max_length=500)
        role = request.form.getlist("roles")

        if not file or not allowed_file(file.filename):
            flash("Invalid file or missing fields!", "danger")
            return redirect(url_for("admin_upload"))

        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)

        if file_size > MAX_FILE_SIZE:
            flash(f"File too large. Maximum size is {MAX_FILE_SIZE / (1024*1024)}MB", "danger")
            return redirect(url_for("admin_upload"))

        original_filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        name, ext = os.path.splitext(original_filename)
        frontend_filename = f"{name}_{timestamp}{ext}"

        frontend_uploads_dir = os.path.join(BASE_DIR, "frontend", "uploads")
        os.makedirs(frontend_uploads_dir, exist_ok=True)
        frontend_upload_path = os.path.join(frontend_uploads_dir, frontend_filename)

        file.save(frontend_upload_path)

        upload_path = os.path.join(app.config["upload_folder"], frontend_filename)
        try:
            shutil.copyfile(frontend_upload_path, upload_path)
        except Exception as e:
            print("Error copying to backup upload folder:", e)

        cursor.execute(
            "INSERT INTO files (filename, description, uploaded_by, uploaded_at, status) VALUES (%s, %s, %s, NOW(), %s)",
            (frontend_filename, desc, session.get("username", "Admin"), "Active"))
        connection.commit()

        log_action(
            user_id=session.get("user_id"),
            username=session.get("username"),
            role=session.get("role"),
            action="file_upload",
            details=f"Uploaded file: {frontend_filename}, Size: {file_size} bytes"
        )

        flash("File uploaded successfully!", "success")
        cursor.close()
        connection.close()
        return redirect(url_for("admin_upload"))

    perm = {"can_upload": True, "can_download": True, "can_delete": True}

    cursor.execute("SELECT * FROM files WHERE status = 'Active' ORDER BY uploaded_at DESC")
    files = cursor.fetchall()

    cursor.close()
    connection.close()

    csrf_token = generate_csrf_token()
    return render_template("admin-2-fileUpload.html", files=files, perm=perm, csrf_token=csrf_token)


@app.route("/download/<filename>")
@require_login
def download_file(filename):
    
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        flash("Invalid filename", "danger")
        
        role = session.get("role", "")
        if role == "employee":
            return redirect(url_for("employee_files", user_id=session.get("user_id")))
        return redirect(url_for("client_file_page"))

    user_id = session.get("user_id")
    role = session.get("role", "")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
    SELECT can_download
    FROM permissions
    WHERE role=%s
    """, (role,))
    perm = cursor.fetchone()

    if not perm or not perm["can_download"]:
        flash("Download permission disabled by admin.", "danger")
        cursor.close()
        conn.close()
        if role == "employee":
            return redirect(url_for("employee_files", user_id=user_id))
        return redirect(url_for("client_file_page"))
    
    cursor.execute("""
        SELECT 1 FROM user_file_access
        WHERE user_id=%s AND filename=%s
    """, (user_id, safe_filename))

    permission = cursor.fetchone()

    cursor.execute("""
        SELECT status FROM files WHERE filename=%s
    """, (safe_filename,))
    file_info = cursor.fetchone()

    cursor.close()
    conn.close()

    if not permission:
        flash("You don't have permission to access this file. Please contact admin.", "danger")
        if role == "employee":
            return redirect(url_for("employee_files", user_id=user_id))
        return redirect(url_for("client_file_page"))

    if not file_info or file_info["status"] != "Active":
        flash("File is not available or has been deleted.", "danger")
        if role == "employee":
            return redirect(url_for("employee_files", user_id=user_id))
        return redirect(url_for("client_file_page"))

    frontend_uploads_dir = os.path.join(BASE_DIR, "frontend", "uploads")
    file_path = os.path.join(frontend_uploads_dir, safe_filename)
    
    if not os.path.abspath(file_path).startswith(os.path.abspath(frontend_uploads_dir)):
        flash("Invalid file path", "danger")
        if role == "employee":
            return redirect(url_for("employee_files", user_id=user_id))
        return redirect(url_for("client_file_page"))

    if not os.path.isfile(file_path):
        flash("File not found on server! Please contact admin.", "danger")
        if role == "employee":
            return redirect(url_for("employee_files", user_id=user_id))
        return redirect(url_for("client_file_page"))

    log_action(
        user_id=session.get("user_id"),
        username=session.get("username"),
        role=session.get("role"),
        action="file_download",
        details=f"Downloaded file: {safe_filename}"
    )

    return send_from_directory(
        frontend_uploads_dir,
        safe_filename,
        as_attachment=True
    )

@app.route("/delete/<filename>")
@require_login
@require_admin
@require_csrf
def delete_file(filename):
    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        flash("Invalid filename", "danger")
        return redirect(url_for("admin_upload"))
    
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("UPDATE files SET status = 'Deleted' WHERE filename = %s", (safe_filename,))
    connection.commit()

    frontend_uploads_dir = os.path.join(BASE_DIR, "frontend", "uploads")
    file_path = os.path.join(frontend_uploads_dir, safe_filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    backup_file_path = os.path.join(app.config["upload_folder"], safe_filename)
    if os.path.exists(backup_file_path):
        os.remove(backup_file_path)

    log_action(
        user_id=session.get("user_id"),
        username=session.get("username"),
        role=session.get("role"),
        action="file_delete",
        details=f"Deleted file: {safe_filename}"
    )

    cursor.close()
    connection.close()
    flash("File deleted successfully!", "success")
    return redirect(url_for("admin_upload"))


# --------------------------------- 8. Rights/Approval/Reject/Creation ------------------------------------------
@app.route("/admin/rights")
@require_login
@require_admin
def admin_rights():
    return render_template("admin-7-rights.html")


@app.route("/api/toggle_user_status/<int:user_id>", methods=["POST"])
@require_login
@require_admin
def toggle_user_status(user_id):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT is_active FROM users WHERE id=%s", (user_id,))
    row = cur.fetchone()

    if not row:
        return {"success": False, "error": "User not found"}

    new_status = 0 if row["is_active"] == 1 else 1

    cur.execute("UPDATE users SET is_active=%s WHERE id=%s", (new_status, user_id))
    conn.commit()

    cur.close()
    conn.close()

    return {"success": True, "new_status": new_status}


@app.route("/api/toggle_user_active/<int:user_id>", methods=["POST"])
@require_login
@require_admin
def toggle_user_active(user_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT is_active FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        new_status = 0 if user["is_active"] else 1
        cursor.execute("UPDATE users SET is_active = %s WHERE id = %s", (new_status, user_id))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({"message": "User status updated successfully", "new_status": new_status}), 200

    except Exception as e:
        print("Error toggling user status:", e)
        return jsonify({"error": str(e)}), 500

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 8.1 User File Access ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
@app.route("/admin/user/<int:user_id>/file-access")
@require_login
@require_admin
def admin_user_file_access(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    cursor.execute("SELECT filename FROM files WHERE status = 'Active'")
    all_files = cursor.fetchall()

    cursor.execute("SELECT filename FROM user_file_access WHERE user_id=%s", (user_id,))
    user_files = cursor.fetchall()

    user_has_file = {f["filename"] for f in user_files}

    cursor.close()
    conn.close()

    csrf_token = generate_csrf_token()
    return render_template("admin_user_file_access.html",
                           user=user,
                           all_files=all_files,
                           user_has_file=user_has_file,
                           csrf_token=csrf_token)

@app.route("/admin/file_access_update", methods=["POST"])
@require_login
@require_admin
@require_csrf
def update_file_access():
    data = request.get_json()
    user_id = data["user_id"]
    filename = data["filename"]
    allow = data["allow"]

    conn = get_db_connection()
    cursor = conn.cursor()

    if allow:
        cursor.execute("""
            INSERT INTO user_file_access (user_id, filename)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE filename = filename
        """, (user_id, filename))
        message = "Access granted successfully."

    else:
        cursor.execute("""
            DELETE FROM user_file_access
            WHERE user_id=%s AND filename=%s
        """, (user_id, filename))
        message = "Access removed successfully."

    conn.commit()
    
    log_audit_event("file_access_updated", user_id=session.get("user_id"), 
                   details=f"User ID: {user_id}, Filename: {filename}, Access: {'granted' if allow else 'revoked'}")
    
    cursor.close()
    conn.close()

    return jsonify({"status": "success", "message": message})


@app.route("/admin/toggle_feature", methods=["POST"])
@require_login
@require_admin
@require_csrf
def toggle_feature():
    data = request.get_json()
    user_id = data.get("uid")
    feature = data.get("feature")

    VALID_FEATURES = ["file_upload", "core_data", "dashboard", "view_meetings", "client_app", "raise_ticket"]

    if feature not in VALID_FEATURES:
        return jsonify({"success": False, "error": "Invalid feature name"}), 400

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute("""
            SELECT is_enabled 
            FROM user_access 
            WHERE user_id=%s AND feature_name=%s
        """, (user_id, feature))
        
        row = cur.fetchone()
        
        if not row:
            cur.execute("""
                INSERT INTO user_access (user_id, feature_name, is_enabled)
                VALUES (%s, %s, 1)
            """, (user_id, feature))
            conn.commit()
            
            log_audit_event("feature_enabled", user_id=session.get("user_id"), 
                           details=f"User ID: {user_id}, Feature: {feature}")
            
            cur.close()
            conn.close()
            return jsonify({"success": True, "new_state": 1})

        current = row["is_enabled"]
        new_state = 0 if current == 1 else 1

        cur.execute("""
            UPDATE user_access
            SET is_enabled=%s
            WHERE user_id=%s AND feature_name=%s
        """, (new_state, user_id, feature))
        conn.commit()

        log_audit_event("feature_toggled", user_id=session.get("user_id"), 
                       details=f"User ID: {user_id}, Feature: {feature}, New State: {'Enabled' if new_state else 'Disabled'}")

        cur.close()
        conn.close()

        return jsonify({"success": True, "new_state": new_state})

    except Exception as e:
        conn.rollback()
        print("ERROR IN toggle_feature:", e)
        if cur:
            cur.close()
        if conn:
            conn.close()
        return jsonify({"success": False, "error": str(e)}), 500



# ------------------------------------ 7. User/Add User ---------------------------------------------
@app.route("/admin/user")
@require_login
@require_admin
def admin_add_user():
    return render_template("admin-8-user.html")

@app.route("/api/admin/add_user", methods=["POST"])
@require_login
@require_admin
@require_csrf
def admin_add_user_api():
    data = request.get_json()
    fullname = sanitize_input(data.get("fullname"), max_length=100)
    username = sanitize_input(data.get("username"), max_length=30)
    email = data.get("email", "").strip().lower()
    password = data.get("password")
    role = data.get("role", "").lower()

    if not all([fullname, username, email, password, role]):
        return jsonify({"error": "All fields are required"}), 400
    
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    if not validate_username(username):
        return jsonify({"error": "Invalid username format"}), 400
    if not validate_password(password):
        return jsonify({"error": "Password does not meet security requirements"}), 400
    if role not in ["admin", "client", "employee"]:
        return jsonify({"error": "Invalid role"}), 400

    hashed_password = generate_password_hash(password)

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "User with this email already exists"}), 400


        cursor.execute("""
        INSERT INTO users (fullname, username, email, password_hash, role, is_verified, is_approved, created_at)
        VALUES (%s, %s, %s, %s, %s, 1, 1, NOW())
        """, (fullname, username, email, hashed_password, role))

        connection.commit()
        
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        new_user = cursor.fetchone()
        
        log_audit_event("user_created", user_id=session.get("user_id"), 
                       details=f"Created user ID: {new_user['id'] if new_user else 'N/A'}, Username: {username}, Role: {role}")
        
        return jsonify({"message": f"User '{username}' added successfully!"}), 201
    except Exception as e:
        connection.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        connection.close()

@app.route("/api/all_users", methods=["GET"])
@require_login
@require_admin
def all_users():
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, fullname, username, email, role, created_at FROM users WHERE is_approved = 1 AND is_verified = 1 AND (role = 'client' OR role = 'employee') ORDER BY created_at")
        users = cursor.fetchall()
        cursor.close()
        connection.close()
        return jsonify(users)
    except Exception as e:
        print("Error fetching all users:", e)
        return jsonify({"error": str(e)}), 500


# ----------------------------------------- 6. CRM -------------------------------------------------------
@app.route("/admin/crm")
@require_login
@require_admin
def admin_crm():
    log_audit_event(
        "crm_dashboard_opened", 
        user_id=session.get("user_id"),
        details="Admin opened CRM dashboard"
    )
    return render_template("admin-6-crm.html")

@app.route("/admin/crm/raise_ticket", methods=["GET", "POST"])
@require_login
@require_csrf
def raise_ticket():
    if request.method == "POST":
        name = sanitize_input(request.form.get("name", ""), max_length=100)
        email = request.form.get("email", "").strip().lower()
        issue = sanitize_input(request.form.get("issue", ""), max_length=200)
        details = sanitize_input(request.form.get("details", ""), max_length=2000)
        
        if not validate_email(email):
            flash("Invalid email format", "danger")
            return render_template("crm_raise_ticket.html", success=False)

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO crm_tickets (name, email, issue, details, created_at) VALUES (%s, %s, %s, %s, NOW())",
            (name, email, issue, details)
        )
        connection.commit()
        
        log_audit_event("ticket_created", user_id=session.get("user_id"), 
                       details=f"Issue: {issue}, Email: {email}")
        
        cursor.close()
        connection.close()

        return render_template("crm_raise_ticket.html", success= True)
    
    if request.method != "POST":
        log_audit_event(
            "crm_raise_ticket_page_opened",
            user_id=session.get("user_id"),
            details="Admin opened Raise Ticket page"
        )

    return render_template("crm_raise_ticket.html", success=False)


@app.route("/admin/crm/view_ticket")
@require_login
@require_admin
def view_ticket():
    issue = request.args.get("issue", "").strip()
    status = request.args.get("status", "")
    start = request.args.get("start", "")
    end = request.args.get("end", "")

    query = "SELECT * FROM crm_tickets WHERE 1=1"
    params = []

    if issue:
        query += " AND issue LIKE %s"
        params.append(f"%{issue}%")

    if status:
        query += " AND status = %s"
        params.append(status)

    if start:
        query += " AND created_at >= %s"
        params.append(start + " 00:00:00")

    if end:
        query += " AND created_at <= %s"
        params.append(end + " 23:59:59")

    query += " ORDER BY created_at DESC"

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute(query, params)
    tickets = cur.fetchall()
    cur.close()
    conn.close()

    log_audit_event(
        "crm_ticket_list_filtered",
        user_id=session.get("user_id"),
        details=f"Filtered Tickets Count: {len(tickets)}"
    )
    # user_prefs = get_admin_prefs()
    # print("DEBUG user_prefs:", user_prefs)
    return render_template("crm_view_ticket.html", tickets=tickets, user_prefs=get_admin_prefs)


@app.route("/admin/crm/ticket/<int:ticket_id>")
@require_login
@require_admin
def admin_view_single_ticket(ticket_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        UPDATE crm_tickets
        SET status = 'Viewed'
        WHERE id = %s AND status IN ('Open', 'new')
    """, (ticket_id,))
    connection.commit()

    # Fetch full ticket details
    cursor.execute("SELECT * FROM crm_tickets WHERE id = %s", (ticket_id,))
    ticket = cursor.fetchone()

    cursor.close()
    connection.close()

    if not ticket:
        flash("Ticket not found", "danger")
        return redirect(url_for("view_ticket"))

    log_audit_event(
        "crm_ticket_opened",
        user_id=session.get("user_id"),
        details=f"Admin opened ticket ID {ticket_id}"
    )
    # user_prefs = get_admin_prefs()
    return render_template("crm_ticket_detail.html", ticket=ticket)



# ------------------------------------------- UPDATE TICKET STATUS -----------------------------------------------------------
@app.route("/admin/crm/ticket/update/<int:ticket_id>", methods=["POST"])
@require_login
@require_admin
def update_ticket_status(ticket_id):
    new_status = request.form.get("status")
    admin_remark = request.form.get("admin_remark", "").strip()

    valid_status = ["Viewed", "In Progress", "Resolved", "Closed"]

    if new_status not in valid_status:
        flash("Invalid status", "danger")
        return redirect(url_for("admin_view_single_ticket", ticket_id=ticket_id))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE crm_tickets
        SET status=%s, admin_remark=%s, updated_at=NOW()
        WHERE id=%s
    """, (new_status, admin_remark, ticket_id))

    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("admin_view_single_ticket", ticket_id=ticket_id))


@app.route("/client/my_tickets")
@require_login
def client_tickets():
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT id, issue, status, created_at, updated_at
        FROM crm_tickets
        WHERE email = %s
        ORDER BY created_at DESC
    """, (session.get("email"),))
    
    tickets = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("client_tickets.html", tickets=tickets)



# --------------------------------------------------- 5. EMPLOYEE MARKET PAGE -------------------------
from datetime import datetime, date, time as time_class, timedelta

def convert_mysql_time(value):
    if isinstance(value, timedelta):
        total_seconds = value.seconds
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        return time_class(hour=hours, minute=minutes, second=seconds)
    return value


from datetime import datetime

@app.route("/admin/employee-market")
@require_login
@require_admin
def admin_employee_market():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM meetings ORDER BY meeting_date DESC, meeting_time DESC")
    rows = cursor.fetchall()
    conn.close()

    all_meetings = []
    today = datetime.now().date()
    current_time = datetime.now().time()

    for row in rows:
        db_status = (row.get("status") or "").lower()

        # ---- DATE PARSE ----
        meeting_date = row["meeting_date"]
        if isinstance(meeting_date, str):
            dt_date = datetime.strptime(meeting_date, "%Y-%m-%d").date()
        else:
            dt_date = meeting_date


        # meeting_time = row["meeting_time"]
        # if isinstance(meeting_time, str):
        #     try:
        #         dt_time = datetime.strptime(meeting_time, "%H:%M:%S").time()
        #     except ValueError:
        #         dt_time = datetime.strptime(meeting_time, "%H:%M").time()
        # else:
        #     dt_time = meeting_time

        # ---- TIME PARSE FIX (supports HH:MM, HH:MM:SS, and timedelta) ----
        meeting_time = row["meeting_time"]
        if isinstance(meeting_time, timedelta):
            dt_time = convert_mysql_time(meeting_time)  # Convert timedelta to time
        elif isinstance(meeting_time, str):
            try:
                dt_time = datetime.strptime(meeting_time, "%H:%M:%S").time()
            except ValueError:
                dt_time = datetime.strptime(meeting_time, "%H:%M").time()
        else:
            dt_time = meeting_time

        # ---- STATUS LOGIC ----
        if db_status == "cancelled":
            status = "Cancelled"
        else:
            if dt_date > today:
                status = "Upcoming"
            # elif dt_date == today and dt_time > current_time:
            elif dt_date == today and dt_time > datetime.now().time():
                status = "Upcoming"
            else:
                status = "Completed"

        all_meetings.append({
            "id": row["id"],
            "employee": row["employee_name"],
            "client": row["client_name"],
            "date": row["meeting_date"],
            "time": row["meeting_time"],
            "purpose": row["purpose"],
            "comments": row.get("comments"),
            "status": status
        })

    return render_template(
        "admin-5-employeeMarket.html",
        meetings=all_meetings
    )



def calculate_meeting_status(meeting_date, meeting_time_str):
    today = datetime.now().date()
    now_time = datetime.now().time()

    if isinstance(meeting_date, str):
        meeting_date = datetime.strptime(meeting_date, "%Y-%m-%d").date()

    try:
        meeting_time = datetime.strptime(meeting_time_str, "%H:%M:%S").time()
    except:
        meeting_time = datetime.strptime(meeting_time_str, "%H:%M").time()

    if meeting_date > today:
        return "Upcoming"
    elif meeting_date == today:
        return "Upcoming" if meeting_time > now_time else "Completed"
    else:
        return "Completed"


def log_meeting_status(meeting_id, status):
    log_action(
        user_id=session.get("user_id"),
        username=session.get("username"),
        role=session.get("role"),
        action="meeting_status_update",
        details=f"Meeting ID {meeting_id} is now {status}"
    )

@app.route("/admin/employee-market/add-meeting", methods=["POST"])
@require_login
@require_admin
@require_csrf
def add_meeting():

    employee_name = sanitize_input(request.form.get("employee_name", ""), max_length=100)
    client_name = sanitize_input(request.form.get("client_name", ""), max_length=100)
    meeting_date = request.form.get("meeting_date", "")
    meeting_time = request.form.get("meeting_time", "")
    purpose = sanitize_input(request.form.get("purpose", ""), max_length=200)
    comments = sanitize_input(request.form.get("comments", ""), max_length=1000)

    status = calculate_meeting_status(meeting_date, meeting_time)

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO meetings 
        (employee_name, client_name, meeting_date, meeting_time, purpose, comments, status)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (employee_name, client_name, meeting_date, meeting_time, purpose, comments, status))

    connection.commit()

    # NEW LOG
    log_action(
        user_id=session.get("user_id"),
        username=session.get("username"),
        role=session.get("role"),
        action="meeting_created",
        details=f"Employee: {employee_name}, Client: {client_name}, Date: {meeting_date}, Time: {meeting_time}"
    )

    cursor.close()
    connection.close()

    flash("Meeting added successfully", "success")
    return redirect(url_for("admin_employee_market"))


@app.route("/admin/employee-market/cancel/<int:meeting_id>", methods=["POST"])
@require_login
@require_admin
def cancel_meeting(meeting_id):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE meetings SET status='Cancelled' WHERE id=%s", (meeting_id,))
    conn.commit()
    cursor.close()
    conn.close()

    # Log cancellation
    log_meeting_status(meeting_id, "Cancelled")

    flash("Meeting cancelled successfully", "success")
    return redirect(url_for("admin_employee_market"))


# ==================================   CLIENT APP/ SOFTWARES ==============================================
@app.route("/admin/client-apps")
@require_login
@require_admin
def admin_client_apps():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM client_apps ORDER BY created_at DESC")
    apps = cursor.fetchall()
    cursor.close()
    conn.close()

    csrf_token = generate_csrf_token()
    return render_template("admin-3-clientApps.html", apps=apps, csrf_token=csrf_token)


@app.route("/admin/client-apps/add", methods=["POST"])
@require_login
@require_admin
@require_csrf
def admin_add_client_app():
    name = sanitize_input(request.form.get("name", ""), max_length=200)
    description = sanitize_input(request.form.get("description", ""), max_length=1000)
    file = request.files.get("file")

    if not name or not description or not file:
        flash("Name, description and file are required", "danger")
        return redirect(url_for("admin_client_apps"))

    # Check file extension - allow .exe and .tar files
    original_filename = secure_filename(file.filename)
    if not original_filename:
        flash("Invalid filename", "danger")
        return redirect(url_for("admin_client_apps"))

    file_ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    if file_ext not in ['exe', 'tar']:
        flash("Only .exe and .tar files are allowed", "danger")
        return redirect(url_for("admin_client_apps"))

    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    MAX_CLIENT_APP_SIZE = 100 * 1024 * 1024  # 100MB for client app files
    if file_size > MAX_CLIENT_APP_SIZE:
        flash(f"File too large. Maximum size is {MAX_CLIENT_APP_SIZE / (1024*1024)}MB", "danger")
        return redirect(url_for("admin_client_apps"))

    # Create directory if it doesn't exist
    client_apps_dir = os.path.join(BASE_DIR, "frontend", "static", "uploads", "client-apps")
    os.makedirs(client_apps_dir, exist_ok=True)

    # Generate unique filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    name_part, ext = os.path.splitext(original_filename)
    filename = f"{name_part}_{timestamp}{ext}"
    
    save_path = os.path.join(client_apps_dir, filename)
    file.save(save_path)

    # Insert into database
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if file_path column exists and add if needed
        cursor.execute("SHOW COLUMNS FROM client_apps")
        columns = [row[0] for row in cursor.fetchall()]  # First element is column name
        
        if 'file_path' not in columns:
            # Add file_path column if it doesn't exist
            try:
                cursor.execute("ALTER TABLE client_apps ADD COLUMN file_path VARCHAR(500) AFTER description")
                conn.commit()
            except Exception as alter_err:
                print(f"Could not add file_path column: {alter_err}")
                # Continue anyway, will try INSERT
        
        # Insert with file_path
        cursor.execute("""
            INSERT INTO client_apps (name, description, file_path)
            VALUES (%s, %s, %s)
        """, (name, description, filename))
        
        conn.commit()
        
        # Log upload
        log_audit_event("client_app_uploaded", user_id=session.get("user_id"), 
                       details=f"Name: {name}, File: {filename}")
        
        flash("App Added Successfully", "success")
    except Exception as e:
        conn.rollback()
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error adding client app: {str(e)}\n{error_trace}")
        flash(f"Error adding app: {str(e)}. Please check database schema.", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("admin_client_apps"))


@app.route("/admin/client-apps/delete/<int:app_id>", methods=["POST"])
@require_login
@require_admin
@require_csrf
def admin_delete_client_app(app_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT file_path FROM client_apps WHERE id=%s", (app_id,))
    app = cursor.fetchone()
    
    if app and app.get('file_path'):
        client_apps_dir = os.path.join(BASE_DIR, "frontend", "static", "uploads", "client-apps")
        file_path = os.path.join(client_apps_dir, app['file_path'])
        if os.path.exists(file_path):
            os.remove(file_path)

    cursor.execute("DELETE FROM client_apps WHERE id=%s", (app_id,))
    cursor.execute("DELETE FROM client_app_permissions WHERE app_id=%s", (app_id,))
    conn.commit()
    
    # Log deletion
    log_audit_event("client_app_deleted", user_id=session.get("user_id"), 
                   details=f"App ID: {app_id}")
    
    cursor.close()
    conn.close()

    flash("App deleted successfully", "success")
    return redirect(url_for("admin_client_apps"))


@app.route("/download/client-app/<int:app_id>")
@require_login
def download_client_app(app_id):
    user_id = session.get("user_id")
    role = session.get("role")

    # Check if user has client_app feature enabled
    if role == "client":
        if not check_feature_access(user_id, "client_app"):
            return render_template("access_denied.html", admin_email="admin@nishgrid.com")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch app info
    cursor.execute("SELECT * FROM client_apps WHERE id=%s", (app_id,))
    app = cursor.fetchone()

    if not app:
        cursor.close()
        conn.close()
        abort(404)

    # If client, check if they have permission
    if role == "client":
        cursor.execute("SELECT * FROM client_app_permissions WHERE client_id=%s AND app_id=%s", (user_id, app_id))
        permission = cursor.fetchone()
        if not permission:
            cursor.close()
            conn.close()
            return render_template("access_denied.html", admin_email="admin@nishgrid.com")

    file_path = app.get("file_path")
    if not file_path:
        cursor.close()
        conn.close()
        abort(404)

    # Log download
    log_audit_event(
        action="client_app_download",
        user_id=user_id,
        details=f"Downloaded app: {app['name']}"
    )

    cursor.close()
    conn.close()

    # Serve file securely
    client_apps_dir = os.path.join(BASE_DIR, "frontend", "static", "uploads", "client-apps")
    return send_from_directory(
        directory=client_apps_dir,
        path=file_path,
        as_attachment=True
    )


@app.route("/employee/core-data")
@require_login
def employee_core_data():
    user_id = session.get("user_id")
    
    # Check if core_data feature is enabled
    if not check_feature_access(user_id, "core_data"):
        return render_template("access_denied.html", admin_email="admin@nishgrid.com")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Create table if it doesn't exist
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_core_data_access (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                core_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_user_core (user_id, core_id)
            )
        """)
        conn.commit()
    except Exception as e:
        print(f"Table creation check: {e}")

    # Fetch core data files that user has access to
    cursor.execute("""
        SELECT cd.*
        FROM core_data cd
        INNER JOIN user_core_data_access ucda ON cd.id = ucda.core_id
        WHERE ucda.user_id = %s
        ORDER BY cd.created_at DESC
    """, (user_id,))
    
    files = cursor.fetchall()
    cursor.close()
    conn.close()

    features = get_user_features(user_id)
    user_prefs = get_user_appearance(user_id)

    return render_template(
        "employee_core_data.html",
        files=files,
        features=features,
        user_prefs=user_prefs
    )


# --------------------------------- for client -----------------------------
@app.route("/client/apps")
@require_login
def client_apps():
    client_id = session["user_id"]
    
    # Check if client_app feature is enabled
    if not check_feature_access(client_id, "client_app"):
        return render_template("access_denied.html", admin_email="admin@nishgrid.com")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Get client name
    cursor.execute("SELECT fullname FROM users WHERE id=%s", (client_id,))
    client = cursor.fetchone()
    client_name = client["fullname"] if client else session.get("username", "Client")
    
    cursor.execute("""
        SELECT ca.*
        FROM client_apps ca
        JOIN client_app_permissions cap ON cap.app_id = ca.id
        WHERE cap.client_id = %s
    """, (client_id,))
    
    apps = cursor.fetchall()
    cursor.close()
    conn.close()

    features = get_client_features(client_id)
    return render_template("client_apps.html", apps=apps, features=features, client_name=client_name)

@app.route("/admin/client-apps/grant", methods=["POST"])
@require_login
@require_admin
@require_csrf
def admin_grant_client_app():
    client_id = request.form.get("client_id")
    app_id = request.form.get("app_id")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT IGNORE INTO client_app_permissions (client_id, app_id)
        VALUES (%s, %s)
    """, (client_id, app_id))
    conn.commit()
    cursor.close()
    conn.close()

    # Log app access change
    log_audit_event("client_app_access_granted", user_id=session.get("user_id"), 
                   details=f"Client ID: {client_id}, App ID: {app_id}")

    return jsonify({"status": "granted"})


@app.route("/admin/client-apps/revoke", methods=["POST"])
@require_login
@require_admin
@require_csrf
def admin_revoke_client_app():
    client_id = request.form.get("client_id")
    app_id = request.form.get("app_id")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        DELETE FROM client_app_permissions
        WHERE client_id=%s AND app_id=%s
    """, (client_id, app_id))
    conn.commit()
    cursor.close()
    conn.close()

    # Log app access change
    log_audit_event("client_app_access_revoked", user_id=session.get("user_id"), 
                   details=f"Client ID: {client_id}, App ID: {app_id}")

    return jsonify({"status": "revoked"})



# ==================================== CORE DATA ========================================================
# import pymysql

@app.route('/admin/core-data')
@require_login
@require_admin
def admin_core_data_page():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM core_data ORDER BY created_at DESC")
    files = cursor.fetchall()
    cursor.close()
    conn.close()

    csrf_token = generate_csrf_token()
    return render_template('admin-4-coreData.html', files=files, csrf_token=csrf_token)


@app.route('/admin/core-data/upload', methods=['POST'])
@require_login
@require_admin
@require_csrf
def admin_upload_core_data():
    title = sanitize_input(request.form.get('title', ''), max_length=200)
    description = sanitize_input(request.form.get('description', ''), max_length=1000)
    file = request.files.get('file')

    if not file or not title:
        flash("Title and file are required", "danger")
        return redirect(url_for('admin_core_data_page'))

    # Check file extension - allow .exe and .tar files
    original_filename = secure_filename(file.filename)
    if not original_filename:
        flash("Invalid filename", "danger")
        return redirect(url_for('admin_core_data_page'))

    file_ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
    if file_ext not in ['exe', 'tar']:
        flash("Only .exe and .tar files are allowed", "danger")
        return redirect(url_for('admin_core_data_page'))

    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    
    MAX_CORE_DATA_SIZE = 100 * 1024 * 1024  # 100MB for core data files
    if file_size > MAX_CORE_DATA_SIZE:
        flash(f"File too large. Maximum size is {MAX_CORE_DATA_SIZE / (1024*1024)}MB", "danger")
        return redirect(url_for('admin_core_data_page'))

    # Create directory if it doesn't exist
    core_data_dir = os.path.join(BASE_DIR, "frontend", "static", "uploads", "core_data")
    os.makedirs(core_data_dir, exist_ok=True)

    # Generate unique filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    name, ext = os.path.splitext(original_filename)
    filename = f"{name}_{timestamp}{ext}"
    
    save_path = os.path.join(core_data_dir, filename)
    file.save(save_path)

    # Insert into database
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO core_data (title, description, file_path) 
            VALUES (%s, %s, %s)
        """, (title, description, filename))
        conn.commit()
        
        # Log upload
        log_audit_event("core_data_uploaded", user_id=session.get("user_id"), 
                       details=f"Title: {title}, File: {filename}")
        
        flash("Core data file uploaded successfully", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error uploading file: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_core_data_page'))


@app.route('/admin/core-data/delete/<int:file_id>')
@require_login
@require_admin
def admin_delete_core_data(file_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT file_path FROM core_data WHERE id=%s", (file_id,))
    file = cursor.fetchone()
    
    if file:
        core_data_dir = os.path.join(BASE_DIR, "frontend", "static", "uploads", "core_data")
        file_path = os.path.join(core_data_dir, file['file_path'])
        if os.path.exists(file_path):
            os.remove(file_path)

    cursor.execute("DELETE FROM core_data WHERE id=%s", (file_id,))
    conn.commit()
    
    # Log deletion
    log_audit_event("core_data_deleted", user_id=session.get("user_id"), 
                   details=f"File ID: {file_id}")
    
    cursor.close()
    conn.close()

    return redirect(url_for('admin_core_data_page'))


@app.route("/admin/core-data/grant", methods=["POST"])
@require_login
@require_admin
def admin_grant_core_data():
    user_id = request.form.get("user_id")
    file_id = request.form.get("file_id")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT IGNORE INTO core_data_user_access (user_id, file_id)
        VALUES (%s, %s)
    """, (user_id, file_id))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "granted"})


@app.route("/admin/core-data/revoke", methods=["POST"])
@require_login
@require_admin
def admin_revoke_core_data():
    user_id = request.form.get("user_id")
    file_id = request.form.get("file_id")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM core_data_user_access
        WHERE user_id=%s AND file_id=%s
    """, (user_id, file_id))
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "revoked"})


from flask import send_from_directory, abort

@app.route("/download/core/<int:file_id>")
@require_login
def download_core_file(file_id):
    user_id = session.get("user_id")
    role = session.get("role")

    # 1. Verify user has Core Data feature enabled
    if not check_feature_access(user_id, "core_data"):
        return render_template("access_denied.html", admin_email="admin@nishgrid.com")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 2. Fetch file info
    cursor.execute("SELECT * FROM core_data WHERE id=%s", (file_id,))
    file = cursor.fetchone()

    if not file:
        cursor.close()
        conn.close()
        abort(404)

    file_path = file["file_path"]

    # 3. Log download event
    log_audit_event(
        action="core_data_download",
        user_id=user_id,
        details=f"Downloaded file: {file_path}"
    )

    cursor.close()
    conn.close()

    # 4. Serve file securely
    return send_from_directory(
        directory="static/uploads/core_data",
        path=file_path,
        as_attachment=True
    )



@app.route("/admin/core-data/grant-access", methods=["POST"])
@require_login
@require_admin
@require_csrf
def admin_grant_core_data_access():
    data = request.get_json()
    uid = data["user_id"]
    cid = data["core_id"]
    allow = data["allow"]

    conn = get_db_connection()
    cur = conn.cursor()

    
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_core_data_access (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                core_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_user_core (user_id, core_id)
            )
        """)
        conn.commit()
    except Exception as e:
        print(f"Table creation check: {e}")

    if allow:
        cur.execute("""
            INSERT IGNORE INTO user_core_data_access (user_id, core_id)
            VALUES (%s, %s)
        """, (uid, cid))
        # Log core data access change
        log_audit_event("core_data_access_granted", user_id=session.get("user_id"), 
                       details=f"User ID: {uid}, Core Data ID: {cid}")
    else:
        cur.execute("""
            DELETE FROM user_core_data_access
            WHERE user_id=%s AND core_id=%s
        """, (uid, cid))
        # Log core data access change
        log_audit_event("core_data_access_revoked", user_id=session.get("user_id"), 
                       details=f"User ID: {uid}, Core Data ID: {cid}")

    conn.commit()
    cur.close()
    conn.close()

    return jsonify({"status": "ok"})


@app.route("/admin/user/<int:uid>/core-data-access")
@require_login
@require_admin
def admin_user_core_data_access(uid):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        flash("User not found", "danger")
        return redirect(url_for("admin_rights"))

    # Create table if it doesn't exist
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_core_data_access (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                core_id INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY unique_user_core (user_id, core_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (core_id) REFERENCES core_data(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
    except Exception as e:
        print(f"Table creation check: {e}")
        # Table might already exist, continue

    cur.execute("SELECT * FROM core_data ORDER BY created_at DESC")
    files = cur.fetchall()

    cur.execute("SELECT core_id FROM user_core_data_access WHERE user_id=%s", (uid,))
    permitted = [row["core_id"] for row in cur.fetchall()]

    cur.close()
    conn.close()

    csrf_token = generate_csrf_token()

    return render_template(
        "admin_user_core_data_access.html",
        user=user,
        core_files=files,
        permitted_ids=permitted,
        csrf_token=csrf_token
    )


# =============================client app=====================================================
@app.route("/admin/user/<int:uid>/client-app-access")
@require_login
@require_admin
def admin_user_client_app_access(uid):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()

    if not user:
        cur.close()
        conn.close()
        flash("User not found", "danger")
        return redirect(url_for("admin_rights"))

    cur.execute("SELECT * FROM client_apps ORDER BY created_at DESC")
    apps = cur.fetchall()

    cur.execute("SELECT app_id FROM client_app_permissions WHERE client_id=%s", (uid,))
    permitted = [row["app_id"] for row in cur.fetchall()]

    cur.close()
    conn.close()

    csrf_token = generate_csrf_token()

    return render_template(
        "admin_user_client_app_access.html",
        user=user,
        apps=apps,
        permitted_ids=permitted,
        csrf_token=csrf_token
    )


# ============================= EMPLOYEE CLIENT ASSIGNMENT =============================
@app.route("/admin/assign-client-to-employee", methods=["POST"])
@require_login
@require_admin
@require_csrf
def assign_client_to_employee():
    data = request.get_json()
    employee_username = data.get("employee_username")
    client_username = data.get("client_username")

    if not employee_username or not client_username:
        return jsonify({"success": False, "error": "Employee username and client username are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if assignment already exists
        cursor.execute("""
            SELECT * FROM employee_clients 
            WHERE employee_username=%s AND client_username=%s
        """, (employee_username, client_username))
        
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"success": False, "error": "Client is already assigned to this employee"}), 400

        # Insert assignment
        cursor.execute("""
            INSERT INTO employee_clients (employee_username, client_username)
            VALUES (%s, %s)
        """, (employee_username, client_username))
        
        conn.commit()
        
        # Log assignment
        log_audit_event("client_assigned_to_employee", user_id=session.get("user_id"), 
                       details=f"Employee: {employee_username}, Client: {client_username}")
        
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Client assigned successfully"})
        
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/admin/remove-client-from-employee", methods=["POST"])
@require_login
@require_admin
@require_csrf
def remove_client_from_employee():
    data = request.get_json()
    employee_username = data.get("employee_username")
    client_username = data.get("client_username")

    if not employee_username or not client_username:
        return jsonify({"success": False, "error": "Employee username and client username are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            DELETE FROM employee_clients
            WHERE employee_username=%s AND client_username=%s
        """, (employee_username, client_username))
        
        conn.commit()
        
        # Log removal
        log_audit_event("client_removed_from_employee", user_id=session.get("user_id"), 
                       details=f"Employee: {employee_username}, Client: {client_username}")
        
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "message": "Client removed successfully"})
        
    except Exception as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": str(e)}), 500


# =================================== Logs ===========================================
@app.route("/admin/logs")
def admin_logs_page():
    return render_template("admin_logs.html")


def add_log(user_id, username, role, action, details=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (user_id, username, role, action, details)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, username, role, action, details))
    conn.commit()
    cursor.close()
    conn.close()


def log_audit_event(action, user_id, role=None, details=""):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        query = """
            INSERT INTO logs (user_id, username, role, action, details)
            VALUES (
                %s,
                (SELECT username FROM users WHERE id = %s),
                (SELECT role FROM users WHERE id = %s),
                %s,
                %s
            )
        """

        cursor.execute(query, (user_id, user_id, user_id, action, details))
        conn.commit()

        cursor.close()
        conn.close()

    except Exception as e:
        print("Logging error:", e)


@app.route("/api/logs", methods=["GET"])
def get_logs():
    try:
        role = request.args.get("role")
        username = request.args.get("username")
        action = request.args.get("action")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))

        query = "SELECT * FROM logs WHERE 1=1"
        count_query = "SELECT COUNT(*) as total FROM logs WHERE 1=1"
        params = []

        if role:
            query += " AND role = %s"
            count_query += " AND role = %s"
            params.append(role)

        if username:
            query += " AND username LIKE %s"
            count_query += " AND username LIKE %s"
            params.append("%" + username + "%")

        if action:
            query += " AND action LIKE %s"
            count_query += " AND action LIKE %s"
            params.append("%" + action + "%")

        if start_date:
            query += " AND DATE(timestamp) >= %s"
            count_query += " AND DATE(timestamp) >= %s"
            params.append(start_date)

        if end_date:
            query += " AND DATE(timestamp) <= %s"
            count_query += " AND DATE(timestamp) <= %s"
            params.append(end_date)

        query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
        offset = (page - 1) * per_page
        params.append(per_page)
        params.append(offset)

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get total count
        count_params = params[:-2]  # Remove LIMIT and OFFSET params
        cursor.execute(count_query, count_params)
        total = cursor.fetchone()["total"]
        
        # Get paginated logs
        cursor.execute(query, params)
        logs = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            "logs": logs,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        })

    except Exception as e:
        print("Fetch Logs Error:", e)
        return jsonify({"error": str(e)}), 500



# ================================= User's Permission =====================================================
@app.route("/api/toggle_permission", methods=["POST"])
@require_login
@require_admin
def toggle_permission():
    data = request.get_json()
    role = data.get("role", "").lower()
    field = data.get("field", "").lower()

    allowed_fields = ["can_download", "can_upload", "can_delete"]
    if field not in allowed_fields:
        return jsonify({"error": "Invalid permission field"}), 400
    
    if role not in ["admin", "client", "employee"]:
        return jsonify({"error": "Invalid role"}), 400
    
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("UPDATE permissions SET {} = NOT {} WHERE role = %s".format(field, field), (role,))
    connection.commit()

    cursor.close()
    connection.close()
    
    return jsonify({"message": "Permission updated successfully"}), 200



# ================================================= EMPLOYEE =======================================================

@app.route("/employee")
@require_login
def employee_home():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login first.", "danger")
        return redirect(url_for("login_page"))

    return redirect(url_for("employee_dashboard", user_id=user_id))


@app.route("/employee/profile")
@require_login
def employee_profile_home():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login first.", "danger")
        return redirect(url_for("login_page"))
    return redirect(url_for("employee_profile", user_id=user_id))


@app.route("/employee/profile/<int:user_id>")
@require_login
def employee_profile(user_id):
    if not verify_user_owns_resource(user_id):
        flash("Access denied", "danger")
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM employees WHERE user_id=%s", (user_id,))
    employee = cursor.fetchone()

    if employee:
        if not employee.get("emp_code") or employee["emp_code"] in ("", None):
            new_code = generate_employee_code()
            cursor2 = conn.cursor()
            cursor2.execute(
                "UPDATE employees SET emp_code=%s WHERE user_id=%s",
                (new_code, user_id)
            )
            conn.commit()
            cursor2.close()
            employee["emp_code"] = new_code
    else:
        new_code = generate_employee_code()
        cursor2 = conn.cursor()
        cursor2.execute(
            "INSERT INTO employees (user_id, emp_code) VALUES (%s, %s)",
            (user_id, new_code)
        )
        conn.commit()
        cursor2.close()
        employee = {"emp_code": new_code}

    features = get_user_features(user_id)

    # Get user details before closing connection
    cursor.execute("SELECT fullname, email FROM users WHERE id=%s", (user_id,))
    user_data = cursor.fetchone()
    
    # Merge employee data with user data
    if employee and user_data:
        employee["fullname"] = user_data.get("fullname") or session.get("username", "Employee")
        employee["email"] = user_data.get("email") or ""
        employee["address"] = employee.get("address") or ""
        employee["contact"] = employee.get("contact") or ""
    elif user_data:
        employee = {
            "emp_code": employee.get("emp_code") if employee else "",
            "fullname": user_data.get("fullname") or session.get("username", "Employee"),
            "email": user_data.get("email") or "",
            "address": employee.get("address") if employee else "",
            "contact": employee.get("contact") if employee else ""
        }
    else:
        employee = {"fullname": session.get("username", "Employee"), "emp_code": "", "email": "", "address": "", "contact": ""}

    cursor.close()
    conn.close()

    user_prefs = get_user_appearance(user_id)   # <- from user_preferences
    
    return render_template(
        "employee_profile.html",
        employee=employee,
        user_id=user_id,
        features=features,
        user_prefs=user_prefs      # <- key name used in base template
    )



@app.route("/employee/<int:user_id>")
@require_login
def employee_dashboard(user_id):
    # SECURITY: Fix IDOR - verify user owns this resource or is admin
    if not verify_user_owns_resource(user_id):
        flash("Access denied", "danger")
        return redirect(url_for("login_page"))
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM employees WHERE user_id=%s", (user_id,))
    emp = cursor.fetchone()

    features = get_user_features(user_id)

    cursor.close()
    conn.close()

  
    user_prefs = get_user_appearance(user_id)
    return render_template(
        "employee_dashboard.html",
        employee=emp,
        user_id=user_id,
        features=features,
        user_prefs=user_prefs
    )



@app.route("/employee/viewmeetings/<int:user_id>")
@require_login
def employee_meetings(user_id):

    if not verify_user_owns_resource(user_id):
        flash("Access denied", "danger")
        return redirect(url_for("login_page"))
    
    session_user_id = session["user_id"]

    if not check_feature_access(session_user_id, "view_meetings"):
        return render_template("access_denied.html", admin_email="nishgridtechnology@gmail.com")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT fullname FROM users WHERE id=%s", (session_user_id,))
    user = cursor.fetchone()
    employee_name = user["fullname"]

    cursor.execute("""
        SELECT * FROM meetings 
        WHERE employee_name = %s
        ORDER BY meeting_date DESC, meeting_time DESC
    """, (employee_name,))
    meetings = cursor.fetchall()

    today = datetime.now().date()
    now_time = datetime.now().time()

    for m in meetings:
        # ... unchanged meeting status logic ...
        pass

    cursor.close()
    conn.close()

    # ⭐ NEW LOG HERE
    log_action(
        user_id=session_user_id,
        username=session.get("username"),
        role=session.get("role"),
        action="meeting_viewed_employee",
        details=f"Employee viewed {len(meetings)} meetings"
    )

    return render_template("employee_meetings.html", meetings=meetings)
    # appearance = get_user_appearance(user_id)

    # return render_template(
    #     "employee_meetings.html",
    #     meetings=meetings,
    #     appearance=appearance
    # )



@app.route("/employee/viewmeetings")
@require_login
def employee_meetings_home():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login first.", "danger")
        return redirect(url_for("login_page"))
    return redirect(url_for("employee_meetings", user_id=user_id))


@app.route("/employee/files/<int:user_id>")
@require_login
def employee_files(user_id):
    
    if not verify_user_owns_resource(user_id):
        flash("Access denied", "danger")
        return redirect(url_for("login_page"))
    
    session_user_id = session["user_id"]

    # 1️ Check if admin allowed file access
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT is_enabled 
        FROM user_access 
        WHERE user_id=%s AND feature_name='file_upload'
    """, (session_user_id,))
    
    row = cursor.fetchone()

    if not row or row["is_enabled"] == 0:
        cursor.close()
        conn.close()
        return render_template("access_denied.html", admin_email="admin@nishgrid.com")

    # Fetch user role for permission controls
    cursor.execute("SELECT role FROM users WHERE id=%s", (session_user_id,))
    user = cursor.fetchone()
    role = user["role"] if user else None

    cursor.execute("""
        SELECT can_download, can_upload, can_delete
        FROM permissions
        WHERE role=%s
    """, (role,))
    perm_row = cursor.fetchone()

    perm = {
        "can_download": bool(perm_row["can_download"]) if perm_row else False,
        "can_upload": bool(perm_row["can_upload"]) if perm_row else False,
        "can_delete": bool(perm_row["can_delete"]) if perm_row else False
    }

    # 2 Admin allowed, fetch only files approved for employee (with full details)
    cursor.execute("""
        SELECT f.filename, f.description, f.uploaded_by, f.uploaded_at
        FROM files f
        INNER JOIN user_file_access ufa ON f.filename = ufa.filename
        WHERE ufa.user_id = %s AND f.status = 'Active'
        ORDER BY f.uploaded_at DESC
    """, (session_user_id,))
    
    files = cursor.fetchall()

    cursor.close()
    conn.close()

    csrf_token = generate_csrf_token()

    # return render_template(
    # "employee_files.html",
    # files=files,
    # perm=perm,
    # role=role,
    # csrf_token=csrf_token,
    # features=get_user_features(user_id)
    # )
    # appearance = get_user_appearance(user_id)
    user_prefs = get_user_appearance(user_id)
    return render_template(
        "employee_files.html",
        files=files,
        perm=perm,
        role=role,
        csrf_token=csrf_token,
        features=get_user_features(user_id),
        user_prefs=user_prefs
    )



@app.route("/employee/files")
@require_login
def employee_files_home():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login first.", "danger")
        return redirect(url_for("login_page"))
    return redirect(url_for("employee_files", user_id=user_id))


@app.route("/employee/files/upload", methods=["POST"])
@require_login
@require_csrf
def employee_upload_file():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login first.", "danger")
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    dict_cursor = conn.cursor(dictionary=True)

    dict_cursor.execute("SELECT role FROM users WHERE id=%s", (user_id,))
    user = dict_cursor.fetchone()
    role = user["role"] if user else None

    dict_cursor.execute("""
        SELECT can_upload
        FROM permissions
        WHERE role=%s
    """, (role,))
    perm = dict_cursor.fetchone()

    if not perm or not perm["can_upload"]:
        dict_cursor.close()
        conn.close()
        flash("You do not have permission to upload files.", "danger")
        return redirect(url_for("employee_files", user_id=user_id))

    file = request.files.get("file")
    desc = sanitize_input(request.form.get("desc", ""), max_length=500)

    if not file or not allowed_file(file.filename):
        dict_cursor.close()
        conn.close()
        flash("Invalid file or missing description.", "danger")
        return redirect(url_for("employee_files", user_id=user_id))

    # Check size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_FILE_SIZE:
        dict_cursor.close()
        conn.close()
        flash(f"File too large. Maximum size is {MAX_FILE_SIZE / (1024*1024)}MB", "danger")
        return redirect(url_for("employee_files", user_id=user_id))

    original_filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    name, ext = os.path.splitext(original_filename)
    unique_filename = f"{name}_{timestamp}{ext}"

    frontend_uploads_dir = os.path.join(BASE_DIR, "frontend", "uploads")
    os.makedirs(frontend_uploads_dir, exist_ok=True)
    upload_path = os.path.join(frontend_uploads_dir, unique_filename)
    file.save(upload_path)

    # Backup copy to default upload folder
    backup_upload_path = os.path.join(app.config["upload_folder"], unique_filename)
    try:
        shutil.copyfile(upload_path, backup_upload_path)
    except Exception as backup_err:
        print("Backup copy failed:", backup_err)

    # Insert file metadata
    dict_cursor.close()

    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO files (filename, description, uploaded_by, uploaded_at, status) VALUES (%s, %s, %s, NOW(), %s)",
        (unique_filename, desc, session.get("username", "Employee"), "Active")
    )
    conn.commit()

    # Grant access to this employee by default
    cursor.execute("""
        INSERT INTO user_file_access (user_id, filename)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE filename = filename
    """, (user_id, unique_filename))
    conn.commit()

    log_action(
    user_id=session.get("user_id"),
    username=session.get("username"),
    role=session.get("role"),
    action="employee_file_upload",
    details=f"Uploaded file: {unique_filename}, Size: {file_size} bytes"
    )


    cursor.close()
    conn.close()

    flash("File uploaded successfully!", "success")
    return redirect(url_for("employee_files", user_id=user_id))


@app.route("/employee/files/delete/<filename>", methods=["POST"])
@require_login
@require_csrf
def employee_delete_file(filename):
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login first.", "danger")
        return redirect(url_for("login_page"))

    safe_filename = secure_filename(filename)
    if not safe_filename or safe_filename != filename:
        flash("Invalid filename.", "danger")
        return redirect(url_for("employee_files", user_id=user_id))

    conn = get_db_connection()
    dict_cursor = conn.cursor(dictionary=True)

    dict_cursor.execute("SELECT role FROM users WHERE id=%s", (user_id,))
    user = dict_cursor.fetchone()
    role = user["role"] if user else None

    dict_cursor.execute("""
        SELECT can_delete
        FROM permissions
        WHERE role=%s
    """, (role,))
    perm = dict_cursor.fetchone()

    if not perm or not perm["can_delete"]:
        dict_cursor.close()
        conn.close()
        flash("You do not have permission to delete files.", "danger")
        return redirect(url_for("employee_files", user_id=user_id))

    dict_cursor.execute("""
        SELECT 1 FROM user_file_access
        WHERE user_id=%s AND filename=%s
    """, (user_id, safe_filename))
    has_access = dict_cursor.fetchone()

    if not has_access:
        dict_cursor.close()
        conn.close()
        flash("You don't have access to this file.", "danger")
        return redirect(url_for("employee_files", user_id=user_id))

    dict_cursor.close()
    # Mark as deleted
    cursor = conn.cursor()
    cursor.execute("UPDATE files SET status='Deleted' WHERE filename=%s", (safe_filename,))
    conn.commit()

    cursor.execute("DELETE FROM user_file_access WHERE filename=%s", (safe_filename,))
    conn.commit()

    frontend_uploads_dir = os.path.join(BASE_DIR, "frontend", "uploads")
    file_path = os.path.join(frontend_uploads_dir, safe_filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    backup_file_path = os.path.join(app.config["upload_folder"], safe_filename)
    if os.path.exists(backup_file_path):
        os.remove(backup_file_path)

    log_action(
    user_id=session.get("user_id"),
    username=session.get("username"),
    role=session.get("role"),
    action="employee_file_delete",
    details=f"Deleted file: {safe_filename}"
    )


    cursor.close()
    conn.close()

    flash("File deleted successfully!", "success")
    return redirect(url_for("employee_files", user_id=user_id))

def get_user_features(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT feature_name, is_enabled FROM user_access WHERE user_id=%s", (user_id,))
    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    # Convert to dict with boolean values
    features = {r["feature_name"]: bool(r["is_enabled"]) for r in rows}
    
    # Ensure defaults
    return {
        "file_upload": features.get("file_upload", False),
        "view_meetings": features.get("view_meetings", False),
        "core_data": features.get("core_data", False),
        "dashboard": features.get("dashboard", False),
    }

@app.route("/api/save_employee_profile", methods=["POST"])
def save_employee_profile():
    data = request.get_json()

    user_id = session.get("user_id")
    fullname = data.get("fullname")
    email = data.get("email")
    #emp_code = data.get("emp_code")
    address = data.get("address")
    contact = data.get("contact")

    conn = get_db_connection()
    cursor = conn.cursor()

    # cursor.execute("""
    #     INSERT INTO employees (user_id, fullname, email, emp_code, address, contact)
    #     VALUES (%s, %s, %s, %s, %s, %s)
    #     ON DUPLICATE KEY UPDATE 
    #         fullname=%s, email=%s, emp_code=%s, address=%s, contact=%s
    # """, (user_id, fullname, email, emp_code, address, contact,
    #       fullname, email, emp_code, address, contact))
    
    # Check if employee record exists, if not create it
    cursor.execute("SELECT id FROM employees WHERE user_id=%s", (user_id,))
    exists = cursor.fetchone()
    
    if not exists:
        # Create employee record if it doesn't exist
        cursor.execute("""
            INSERT INTO employees (user_id, fullname, email, address, contact)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, fullname, email, address, contact))
    else:
        # Update existing record
        cursor.execute("""
            UPDATE employees
            SET fullname=%s, email=%s, address=%s, contact=%s
            WHERE user_id=%s
        """, (fullname, email, address, contact, user_id))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "message": "Profile updated successfully"})


def generate_employee_code():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT emp_code FROM employees ORDER BY emp_code DESC LIMIT 1")
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row or not row[0]:
        return "Emp001"

    last_code = row[0]  
    number = int(last_code.replace("Emp", "")) + 1
    return f"Emp{number:03d}"

@app.route("/employee/crm")
@require_login
def employee_crm():
    # Redirect to meetings page like client CRM
    return redirect(url_for("employee_crm_meetings"))


@app.route("/employee/crm/meetings")
@require_login
def employee_crm_meetings():
    employee_username = session["username"]
    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Dropdown: only assigned clients
    cursor.execute("""
        SELECT client_username AS name
        FROM employee_clients
        WHERE employee_username = %s
    """, (employee_username,))
    customers = cursor.fetchall()

    # Meetings only for this employee
    cursor.execute("""
        SELECT *
        FROM meetings
        WHERE employee_name = %s
        ORDER BY meeting_date DESC, meeting_time DESC
    """, (employee_username,))
    meetings = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "employee_meetings_crm.html",
        customers=customers,
        meetings=meetings,
        employee_name=employee_username,
        features=get_user_features(user_id)
    )


@app.route("/employee/crm/add", methods=["GET", "POST"])
@require_login
def employee_add_meeting():
    employee_username = session["username"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT client_username AS name
        FROM employee_clients
        WHERE employee_username = %s
    """, (employee_username,))
    customers = cursor.fetchall()

    if request.method == "POST":
        client = request.form["client_name"]
        date = request.form["meeting_date"]
        time = request.form["meeting_time"]
        purpose = request.form["purpose"]

        cursor.execute("""
            INSERT INTO meetings
            (employee_name, client_name, meeting_date, meeting_time, purpose)
            VALUES (%s, %s, %s, %s, %s)
        """, (employee_username, client, date, time, purpose))

        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for("employee_crm_meetings"))

    cursor.close()
    conn.close()
    return render_template("employee_add_meeting.html", customers=customers, features=get_user_features(session["user_id"]))


# ------------------------------- ADD CUSTOMER -------------------------------
@app.route("/employee/crm/add-customer", methods=["GET", "POST"])
@require_login
def employee_add_customer():
    user_id = session["user_id"]
    employee_username = session["username"]

    if request.method == "POST":
        fullname = request.form["fullname"]
        username = request.form["username"]
        email = request.form.get("email")

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT IGNORE INTO users (username, fullname, email, role, is_active)
            VALUES (%s, %s, %s, 'client', 1)
        """, (username, fullname, email))

        cursor.execute("""
            INSERT INTO employee_clients (employee_username, client_username)
            VALUES (%s, %s)
        """, (employee_username, username))

        conn.commit()
        cursor.close()
        conn.close()

        return redirect(url_for("employee_crm"))

    return render_template(
        "employee_add_customer.html",
        features=get_user_features(user_id)
    )



@app.route('/employee/set-theme', methods=['POST'])
def set_theme():
    data = request.get_json()
    theme = data['theme']
    user_id = session['user_id']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE employees SET theme=%s WHERE id=%s", (theme, user_id))
    conn.commit()
    cursor.close()
    conn.close()

    session['theme'] = theme  # store for current session

    return jsonify(success=True)



# ================================================= CLIENT =========================================================

@app.route("/api/save_client_profile", methods=["POST"])
def save_client_profile():
    data = request.get_json()

    user_id = session.get("user_id")
    address = data.get("address")
    contact = data.get("contact")
    service = data.get("service")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO client_profiles (user_id, address, contact, service)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE 
            address=%s, contact=%s, service=%s
    """, (user_id, address, contact, service, address, contact, service))

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "success"})

def get_client_features(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT feature_name, is_enabled
        FROM user_access
        WHERE user_id = %s
    """, (user_id,))

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    # Convert rows → dict
    features = {row["feature_name"]: bool(row["is_enabled"]) for row in rows}

    # Ensure defaults (VERY IMPORTANT)
    return {
        "profile": True,
        "file_upload": features.get("file_upload", False),
        "view_meetings": features.get("view_meetings", False),
        "raise_ticket": features.get("raise_ticket", False),
        "client_app": features.get("client_app", False),
        "dashboard": features.get("dashboard", False),
    }


@app.route("/client")
@require_login
def client_dashboard():
    user_id = session.get("user_id")

    conn = get_db_connection()
    cursor = get_db_cursor(conn)

    cursor.execute("SELECT fullname FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()
    return render_template(
        "client_home.html",
        client_name=user["fullname"] if user else "Client",
        features=get_client_features(user_id)
    )


@app.route("/client_dashboard")
@require_login
def client_dashboard_alias():
    return redirect(url_for("client_dashboard"))


# @app.route("/client/profile")
# @require_login
# def client_profile():
#     user_id = session.get("user_id")

#     conn = get_db_connection()
#     cursor = get_db_cursor(conn)

#     cursor.execute("SELECT fullname FROM users WHERE id = %s", (user_id,))
#     user = cursor.fetchone()

#     cursor.execute("""
#         SELECT address, contact, service
#         FROM client_profiles
#         WHERE user_id = %s
#     """, (user_id,))
#     profile = cursor.fetchone()

#     cursor.close()
#     conn.close()
#     '''features = {
#         "profile": True,
#         "file_upload": False,
#         "view_meetings": True,
#         "raise_ticket": False
#     }'''


#     return render_template(
#         "client_profile.html",
#         full_name=user["fullname"] if user else "",
#         client_name=user["fullname"] if user else "Client",
#         profile=profile,
#         features=get_client_features(user_id)
#     )


@app.route("/client/profile")
@require_login
def client_profile():
    user_id = session.get("user_id")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT fullname FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return "User not found", 404

    full_name = user["fullname"]

    cursor.execute("""
        SELECT address, contact, service 
        FROM client_profiles
        WHERE user_id=%s
    """, (user_id,))
    profile = cursor.fetchone()

    cursor.execute("SELECT avatar_url FROM customers WHERE fullname=%s", (full_name,))
    customer = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template(
        "client_profile.html",
        full_name=user["fullname"] if user else "",
        client_name=user["fullname"] if user else "Client",
        profile=profile,
        avatar_url=customer["avatar_url"] if customer and customer["avatar_url"] else None,
        features=get_client_features(user_id)
    )



@app.route("/client/files", methods=["GET"])
@require_login
def client_file_page():
    user_id = session["user_id"]

    if not check_feature_access(user_id, "file_upload"):
        return render_template("access_denied.html", admin_email="admin@nishgrid.com")

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT role FROM users WHERE id = %s", (user_id,))
    role = cursor.fetchone()["role"]

    cursor.execute("""
        SELECT can_download, can_upload, can_delete
        FROM permissions
        WHERE role = %s
    """, (role,))
    perm = cursor.fetchone()

    cursor.execute("""
    SELECT 
        f.filename,
        f.description,
        f.uploaded_at,
        u.fullname AS uploaded_by_name
    FROM files f
    INNER JOIN user_file_access ufa 
            ON f.filename = ufa.filename
    INNER JOIN users u 
            ON u.username = f.uploaded_by
    WHERE ufa.user_id = %s
      AND f.status = 'Active'
    ORDER BY f.uploaded_at DESC
""", (user_id,))


    files = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        "client_files.html",
        files=files,
        perm=perm,
        role=role,
        features=get_client_features(user_id),
        client_name=session.get("fullname")  
    )


@app.route("/client/crm")
@require_login
def client_crm():
    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    
    cursor.execute("""
        SELECT id, fullname AS name, city, mobile, status, priority
        FROM customers   -- or your table name
        WHERE owner_id = %s
        ORDER BY name
    """, (user_id,))
    customers = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "client_crm.html",          # CRM page
        client_name=session.get("username"),
        customers=customers,
        features=get_client_features(user_id)
    )


@app.route("/client/meetings")
@require_login
def client_meetings():
    username = session.get("username")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT employee_name, meeting_date, meeting_time, purpose, status, comments
        FROM meetings
        WHERE client_name = %s
        ORDER BY meeting_date DESC, meeting_time DESC
    """, (username,))
    meetings = cursor.fetchall()

    cursor.execute("""
        SELECT DISTINCT employee_name AS name
        FROM meetings
        WHERE client_name = %s
        ORDER BY employee_name
    """, (username,))
    customers = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "client_meetings_crm.html",
        meetings=meetings,
        customers=customers,
        client_name=username,
        features=get_client_features(session["user_id"])
    )


@app.route("/client/crm/meetings")
@require_login
def client_meetings_crm():
    username = session.get("username")  # client username or fullname used in meetings

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Fetch meetings only for this client
    cursor.execute("""
        SELECT 
            employee_name,
            client_name,
            meeting_date,
            meeting_time,
            purpose,
            status,
            comments AS notes
        FROM meetings
        WHERE client_name = %s
        ORDER BY meeting_date DESC, meeting_time DESC
    """, (username,))
    meetings = cursor.fetchall()

    # 2️⃣ Fetch only related names for dropdown (from those meetings)
    cursor.execute("""
        SELECT DISTINCT employee_name AS name
        FROM meetings
        WHERE client_name = %s
        ORDER BY employee_name
    """, (username,))
    customers = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "client_meetings_crm.html",
        meetings=meetings,
        customers=customers,
        client_name=username,
        features=get_client_features(session["user_id"])
    )


def check_feature_access(user_id, feature_name):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT is_enabled FROM user_access 
        WHERE user_id=%s AND feature_name=%s
    """, (user_id, feature_name))

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    return bool(row and row["is_enabled"])


@app.route("/raise-ticket")
@require_login
def raise_ticket_unified():
    role = session.get("role")
    user_id = session.get("user_id")

    if role == "client":
        return render_template(
            "client_raise_ticket.html",
            success=False,
            client_name=session.get("username"),
            features=get_client_features(user_id)
        )
    else:
        return render_template(
            "employee_raise_ticket.html",
            success=False
        )


# ======================================== VIEW RAISED TICKET =======================================================
@app.route("/raise-ticket/submit", methods=["POST"])
@require_login
def submit_ticket():
    user_id = session["user_id"]
    role = session["role"]

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    issue = request.form.get("issue_type", "").strip()
    details = request.form.get("details", "").strip()
    file_desc = request.form.get("file_desc", "").strip()

    file = request.files.get("file")

    if not issue or not details:
        return jsonify({
            "status": "error",
            "error": "Issue and details are required."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Autofill name/email for logged-in users if form left blank
        if not name or not email:
            cursor.execute("SELECT fullname, email FROM users WHERE id=%s", (user_id,))
            u = cursor.fetchone()
            if u:
                # tuple cursor: (fullname, email)
                name = name or (u[0] or session.get("username") or "").strip()
                email = email or (u[1] or "").strip()

        # Detect table schema and insert accordingly (supports older schemas)
        cursor.execute("SHOW COLUMNS FROM crm_tickets")
        cols = {row[0] for row in cursor.fetchall()}

        if {"user_id", "status"}.issubset(cols):
            cursor.execute(
                """
                INSERT INTO crm_tickets (user_id, name, email, issue, details, status)
                VALUES (%s, %s, %s, %s, %s, 'open')
                """,
                (user_id, name, email, issue, details),
            )
        else:
            # Fallback: older table without user_id/status columns
            cursor.execute(
                """
                INSERT INTO crm_tickets (name, email, issue, details, created_at)
                VALUES (%s, %s, %s, %s, NOW())
                """,
                (name, email, issue, details),
            )

        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        cursor.close()
        conn.close()
        return jsonify({"status": "error", "error": f"Ticket submit failed: {str(e)}"}), 500

    cursor.close()
    conn.close()

    # flash("Ticket raised successfully!", "success")
    # return redirect(url_for("my_tickets"))

    return jsonify({
        "status": "success",
        "message": "Ticket submitted successfully"
    })


# --------------------------------------------- My Ticket -------------------------------------
@app.route("/my-tickets")
@require_login
def my_tickets():
    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, issue, status, created_at, updated_at
        FROM crm_tickets
        WHERE user_id = %s
        ORDER BY created_at DESC
    """, (user_id,))

    tickets = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("my_tickets.html", tickets=tickets)


# --------------------------------------- Avatar saving/removing --------------------------------

# @app.route("/client/upload-avatar", methods=["POST"])
# @require_login
# def upload_avatar():
#     user_id = session.get("user_id")
#     file = request.files.get("avatar")

#     if not file:
#         return jsonify({"error": "No file"}), 400

#     filename = secure_filename(file.filename)
#     ext = os.path.splitext(filename)[1]
#     new_filename = f"avatar_{user_id}_{int(time.time())}{ext}"

#     save_path = os.path.join("static/uploads/avatars", new_filename)
#     os.makedirs(os.path.dirname(save_path), exist_ok=True)
#     file.save(save_path)

#     avatar_url = f"/static/uploads/avatars/{new_filename}"

#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute("UPDATE customers SET avatar_url=%s WHERE owner_id=%s", (avatar_url, user_id))
#     conn.commit()
#     cursor.close()
#     conn.close()

#     return jsonify({"success": True, "avatar_url": avatar_url})





import os
import time
from flask import jsonify, request, session
from werkzeug.utils import secure_filename

# ============================================ AVATAR STORAGE =====================================================
# Separate from regular file uploads - for profile pictures only
AVATAR_UPLOAD_FOLDER = os.path.join(BASE_DIR, "frontend", "static", "avatars")
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB limit for avatars
ALLOWED_AVATAR_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Create avatar folder if it doesn't exist
os.makedirs(AVATAR_UPLOAD_FOLDER, exist_ok=True)

@app.route("/client/upload-avatar", methods=["POST"])
@require_login
def upload_avatar():
    user_id = session.get("user_id")
    fullname = session.get("fullname")
    
    file = request.files.get("avatar")
    
    if not file:
        return jsonify({"error": "No file provided"}), 400
    
    if not fullname:
        return jsonify({"error": "User fullname not found"}), 400
    
    try:
        # 1. Validate filename
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        # 2. Validate extension
        filename = secure_filename(file.filename)
        if '.' not in filename:
            return jsonify({"error": "Invalid file format"}), 400
        
        ext = filename.rsplit('.', 1)[1].lower()
        if ext not in ALLOWED_AVATAR_EXTENSIONS:
            return jsonify({"error": f"Only {', '.join(ALLOWED_AVATAR_EXTENSIONS)} files allowed"}), 400
        
        # 3. Validate file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_AVATAR_SIZE:
            return jsonify({"error": f"File too large. Max {MAX_AVATAR_SIZE / (1024*1024)}MB"}), 400
        
        if file_size == 0:
            return jsonify({"error": "Empty file"}), 400
        
        # 4. Generate unique filename
        timestamp = int(time.time())
        new_filename = f"avatar_{user_id}_{timestamp}.{ext}"
        save_path = os.path.join(AVATAR_UPLOAD_FOLDER, new_filename)
        
        # 5. Save file
        file.save(save_path)
        
        # 6. Verify file was saved
        if not os.path.exists(save_path):
            return jsonify({"error": "File save failed - permission issue"}), 500
        
        # 7. Avatar URL (relative to static folder)
        avatar_url = f"/static/avatars/{new_filename}"
        
        # 8. Update database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE customers SET avatar_url=%s WHERE owner_id=%s", 
            (avatar_url, user_id)
        )
        
        if cursor.rowcount == 0:
            # Customer record doesn't exist, create it
            cursor.execute(
                "INSERT INTO customers (owner_id, avatar_url) VALUES (%s, %s)",
                (user_id, avatar_url)
            )
        
        conn.commit()
        cursor.close()
        conn.close()
        
        print(f"✓ Avatar uploaded: {new_filename} (Size: {file_size} bytes)")
        
        return jsonify({"success": True, "avatar_url": avatar_url})
    
    except Exception as e:
        print(f"✗ Avatar upload error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Upload failed: {str(e)}"}), 500


@app.route("/client/remove-avatar", methods=["POST"])
@require_login
def remove_avatar():
    user_id = session.get("user_id")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get current avatar URL
        cursor.execute("SELECT avatar_url FROM customers WHERE owner_id=%s", (user_id,))
        row = cursor.fetchone()
        
        if row and row["avatar_url"]:
            # Delete file from disk
            file_path = os.path.join(AVATAR_UPLOAD_FOLDER, os.path.basename(row["avatar_url"]))
            
            if os.path.exists(file_path):
                os.remove(file_path)
                print(f"✓ Avatar file deleted: {file_path}")
            
            # Clear avatar_url from database
            cursor.execute("UPDATE customers SET avatar_url=NULL WHERE owner_id=%s", (user_id,))
            conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({"success": True})
    
    except Exception as e:
        print(f"✗ Avatar remove error: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route("/client/get-avatar", methods=["GET"])
@require_login
def get_avatar():
    user_id = session.get("user_id")
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT avatar_url FROM customers WHERE owner_id=%s", (user_id,))
        row = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        if row and row["avatar_url"]:
            # Verify file exists on disk
            file_path = os.path.join(AVATAR_UPLOAD_FOLDER, os.path.basename(row["avatar_url"]))
            if os.path.exists(file_path):
                print(f"✓ Avatar found: {row['avatar_url']}")
                return jsonify({"avatar_url": row["avatar_url"]})
            else:
                # File doesn't exist, clear from database
                cursor = conn.cursor()
                cursor.execute("UPDATE customers SET avatar_url=NULL WHERE owner_id=%s", (user_id,))
                conn.commit()
                cursor.close()
                print(f"⚠ Avatar URL in DB but file missing for user {user_id}")
                return jsonify({"avatar_url": None})
        
        return jsonify({"avatar_url": None})
    
    except Exception as e:
        print(f"✗ Avatar retrieval error: {str(e)}")
        return jsonify({"avatar_url": None})







# import os
# import time
# from flask import jsonify, request, session
# from werkzeug.utils import secure_filename

# UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads", "avatars")

# @app.route("/client/upload-avatar", methods=["POST"])
# @require_login
# def upload_avatar():
#     user_id = session.get("user_id")
#     fullname = session.get("fullname")
    
#     file = request.files.get("avatar")
    
#     if not file:
#         return jsonify({"error": "No file"}), 400
    
#     if not fullname:
#         return jsonify({"error": "User fullname not found"}), 400
    
#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
    
#     # Save file
#     filename = secure_filename(file.filename)
#     ext = os.path.splitext(filename)[1]
#     new_filename = f"avatar_{fullname}_{int(time.time())}{ext}"
#     save_path = os.path.join(UPLOAD_FOLDER, new_filename)
    
#     os.makedirs(UPLOAD_FOLDER, exist_ok=True)
#     file.save(save_path)
    
#     avatar_url = f"/static/uploads/avatars/{new_filename}"
    
#     # Update customers table using owner_id (which is user_id)
#     cursor.execute(
#         "UPDATE customers SET avatar_url=%s WHERE owner_id=%s", 
#         (avatar_url, user_id)
#     )
    
#     conn.commit()
#     cursor.close()
#     conn.close()
    
#     return jsonify({"success": True, "avatar_url": avatar_url})


# @app.route("/client/remove-avatar", methods=["POST"])
# @require_login
# def remove_avatar():
#     user_id = session.get("user_id")
    
#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
    
#     # Get avatar using owner_id (which is user_id)
#     cursor.execute("SELECT avatar_url FROM customers WHERE owner_id=%s", (user_id,))
#     row = cursor.fetchone()
    
#     if row and row["avatar_url"]:
#         file_path = os.path.join(app.root_path, row["avatar_url"].lstrip("/"))
#         if os.path.exists(file_path):
#             os.remove(file_path)
        
#         # Clear avatar_url from database
#         cursor.execute("UPDATE customers SET avatar_url=NULL WHERE owner_id=%s", (user_id,))
#         conn.commit()
    
#     cursor.close()
#     conn.close()
    
#     return jsonify({"success": True})


# @app.route("/client/get-avatar", methods=["GET"])
# @require_login
# def get_avatar():
#     user_id = session.get("user_id")
    
#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
    
#     cursor.execute("SELECT avatar_url FROM customers WHERE owner_id=%s", (user_id,))
#     row = cursor.fetchone()
    
#     cursor.close()
#     conn.close()
    
#     if row and row["avatar_url"]:
#         return jsonify({"avatar_url": row["avatar_url"]})
    
#     return jsonify({"avatar_url": None})


# import os
# import time
# from flask import jsonify, request, session
# from werkzeug.utils import secure_filename

# UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads", "avatars")

# @app.route("/client/upload-avatar", methods=["POST"])
# @require_login
# def upload_avatar():
#     user_id = session.get("user_id")
#     fullname = session.get("fullname")  # Get fullname from session
    
#     file = request.files.get("avatar")
    
#     if not file:
#         return jsonify({"error": "No file"}), 400
    
#     if not fullname:
#         return jsonify({"error": "User fullname not found"}), 400
    
#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
    
#     # Save file
#     filename = secure_filename(file.filename)
#     ext = os.path.splitext(filename)[1]
#     new_filename = f"avatar_{fullname}_{int(time.time())}{ext}"
#     save_path = os.path.join(UPLOAD_FOLDER, new_filename)
    
#     os.makedirs(UPLOAD_FOLDER, exist_ok=True)
#     file.save(save_path)
    
#     avatar_url = f"/static/uploads/avatars/{new_filename}"
    
#     # Update customers table using fullname
#     cursor.execute(
#         "UPDATE customers SET avatar_url=%s WHERE fullname=%s", 
#         (avatar_url, fullname)
#     )
    
#     conn.commit()
#     cursor.close()
#     conn.close()
    
#     return jsonify({"success": True, "avatar_url": avatar_url})


# @app.route("/client/remove-avatar", methods=["POST"])
# @require_login
# def remove_avatar():
#     fullname = session.get("fullname")
    
#     if not fullname:
#         return jsonify({"error": "User fullname not found"}), 400
    
#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
    
#     # Get avatar using fullname
#     cursor.execute("SELECT avatar_url FROM customers WHERE fullname=%s", (fullname,))
#     row = cursor.fetchone()
    
#     if row and row["avatar_url"]:
#         file_path = os.path.join(app.root_path, row["avatar_url"].lstrip("/"))
#         if os.path.exists(file_path):
#             os.remove(file_path)
        
#         # Clear avatar_url from database
#         cursor.execute("UPDATE customers SET avatar_url=NULL WHERE fullname=%s", (fullname,))
#         conn.commit()
    
#     cursor.close()
#     conn.close()
    
#     return jsonify({"success": True})


# @app.route("/client/get-avatar", methods=["GET"])
# @require_login
# def get_avatar():
#     fullname = session.get("fullname")
    
#     if not fullname:
#         return jsonify({"avatar_url": None})
    
#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
    
#     cursor.execute("SELECT avatar_url FROM customers WHERE fullname=%s", (fullname,))
#     row = cursor.fetchone()
    
#     cursor.close()
#     conn.close()
    
#     if row and row["avatar_url"]:
#         return jsonify({"avatar_url": row["avatar_url"]})
    
#     return jsonify({"avatar_url": None})


# import os
# import time
# from flask import jsonify, request, session
# from werkzeug.utils import secure_filename

# UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads", "avatars")


# @app.route("/client/upload-avatar", methods=["POST"])
# @require_login
# def upload_avatar():
#     user_id = session.get("user_id")
#     file = request.files.get("avatar")

#     if not file:
#         return jsonify({"error": "No file"}), 400

#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)

#     # get fullname for lookup
#     cursor.execute("SELECT fullname FROM users WHERE id=%s", (user_id,))
#     user = cursor.fetchone()
#     full_name = user["fullname"]

#     # save file
#     filename = secure_filename(file.filename)
#     ext = os.path.splitext(filename)[1]
#     new_filename = f"avatar_{full_name}_{int(time.time())}{ext}"

#     save_path = os.path.join("static/uploads/avatars", new_filename)
#     os.makedirs(os.path.dirname(save_path), exist_ok=True)
#     file.save(save_path)

#     avatar_url = f"/static/uploads/avatars/{new_filename}"

#     # update customers table
#     cursor.execute("UPDATE customers SET avatar_url=%s WHERE fullname=%s", (avatar_url, full_name))
#     conn.commit()

#     cursor.close()
#     conn.close()

#     return jsonify({"success": True, "avatar_url": avatar_url})

# @app.route("/client/remove-avatar", methods=["POST"])
# @require_login
# def remove_avatar():
#     user_id = session.get("user_id")

#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)

#     cursor.execute("SELECT fullname FROM users WHERE id=%s", (user_id,))
#     user = cursor.fetchone()
#     full_name = user["fullname"]

#     cursor.execute("SELECT avatar_url FROM customers WHERE fullname=%s", (full_name,))
#     row = cursor.fetchone()

#     if row and row["avatar_url"]:
#         file_path = os.path.join(app.root_path, row["avatar_url"].lstrip("/"))
#         if os.path.exists(file_path):
#             os.remove(file_path)

#         cursor.execute("UPDATE customers SET avatar_url=NULL WHERE fullname=%s", (full_name,))
#         conn.commit()

#     cursor.close()
#     conn.close()

#     return jsonify({"success": True})



# @app.route("/client/upload-avatar", methods=["POST"])
# @require_login
# def upload_avatar():
#     user_id = session.get("user_id")
#     file = request.files.get("avatar")

#     if not file:
#         return jsonify({"error": "No file provided"}), 400

#     os.makedirs(UPLOAD_FOLDER, exist_ok=True)

#     ext = os.path.splitext(file.filename)[1]
#     filename = secure_filename(f"avatar_{user_id}_{int(time.time())}{ext}")

#     save_path = os.path.join(UPLOAD_FOLDER, filename)
#     file.save(save_path)

#     avatar_url = f"/static/uploads/avatars/{filename}"

#     conn = get_db_connection()
#     cursor = conn.cursor()

#     cursor.execute(
#         "UPDATE customers SET avatar_url=%s WHERE owner_id=%s",
#         (avatar_url, user_id)
#     )
#     conn.commit()
#     cursor.close()
#     conn.close()

#     return jsonify({"success": True, "avatar_url": avatar_url})


# @app.route("/client/remove-avatar", methods=["POST"])
# @require_login
# def remove_avatar():
#     user_id = session.get("user_id")

#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
#     cursor.execute("SELECT avatar_url FROM customers WHERE owner_id=%s", (user_id,))
#     row = cursor.fetchone()

#     if row and row["avatar_url"]:
#         file_path = os.path.join(app.root_path, row["avatar_url"].lstrip("/"))
#         if os.path.exists(file_path):
#             os.remove(file_path)

#         cursor.execute(
#             "UPDATE customers SET avatar_url=NULL WHERE owner_id=%s",
#             (user_id,)
#         )
#         conn.commit()

#     cursor.close()
#     conn.close()

#     return jsonify({"success": True})



# @app.route("/client/remove-avatar", methods=["POST"])
# @require_login
# def remove_avatar():
#     user_id = session.get("user_id")

#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
#     cursor.execute("SELECT avatar_url FROM customers WHERE owner_id=%s", (user_id,))
#     row = cursor.fetchone()

#     if row and row["avatar_url"]:
#         try:
#             os.remove(row["avatar_url"].lstrip("/"))
#         except FileNotFoundError:
#             pass
    
#     cursor.execute("UPDATE customers SET avatar_url=NULL WHERE owner_id=%s", (user_id,))
#     conn.commit()
#     cursor.close()
#     conn.close()

#     return jsonify({"success": True})


# ================================================ MAIN FNUNCTION ====================================================
if __name__ == "__main__":
    license_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuaXNoZ3JpZHRlY2hub2xvZ3lAZ21haWwuY29tIiwiaWF0IjoxNzYyODU5NTA0LCJleHAiOjE3OTQzOTU1MDQsImZlYXR1cmVzIjpbInBybyJdfQ.ak2Slh8Ue-tacQJ-Z258pdyEdAaKul9jMQuxuCdmTWs";
    if validate_license(license_key):
        try:
            app.run(host='0.0.0.0', port=5503, debug=True)
        except OSError:
            app.run(host='0.0.0.0', port=5001, debug=True)
    else: 
        print("License validation failed. Appliaction will not strt")

