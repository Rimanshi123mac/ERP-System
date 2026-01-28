# app/security.py
import os
from functools import wraps
from flask import request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import jwt
from datetime import datetime, timedelta


def init_security(app):
    """Initialize security features for Flask app"""
    origins = os.getenv("FRONTEND_ORIGIN", "*")
    CORS(app, origins=origins, supports_credentials=True)

    # Add secure headers (CSP, HSTS, etc.)
    Talisman(app, content_security_policy=None)  # set stricter CSP later if needed

    # Rate limiting
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["100 per 15 minutes"]
    )
    limiter.init_app(app)
    app.limiter = limiter

def sign_token(payload: dict) -> str:
    """Create a JWT"""
    secret = os.getenv("JWT_SECRET")
    expiry = int(os.getenv("TOKEN_EXPIRY_SECONDS", "3600"))

    token = jwt.encode(
        {**payload, "exp": datetime.utcnow() + timedelta(seconds=expiry)},
        secret,
        algorithm="HS256"
    )
    return token


def authenticate_jwt(f):
    """Decorator to protect routes with JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization") or request.cookies.get("token")
        if not auth:
            return jsonify({"error": "Missing auth"}), 401

        token = auth.split(" ")[1] if auth.startswith("Bearer ") else auth
        try:
            payload = jwt.decode(token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        request.user = payload
        return f(*args, **kwargs)
    return decorated
