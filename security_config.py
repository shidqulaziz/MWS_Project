import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import session, request, jsonify, redirect, url_for
import time
from collections import defaultdict

class SecurityConfig:
    # Generate secure secret key
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    
    # Rate limiting
    RATE_LIMIT_STORAGE = defaultdict(list)
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 300  # 5 minutes
    
    # Session security
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True  # No JavaScript access
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour

def secure_hash_password(password):
    """Hash password dengan salt menggunakan Werkzeug"""
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

def verify_password(password, hash):
    """Verifikasi password"""
    return check_password_hash(hash, password)

def rate_limit_check(identifier, max_attempts=5, window=300):
    """Rate limiting untuk login attempts"""
    now = time.time()
    attempts = SecurityConfig.RATE_LIMIT_STORAGE[identifier]
    
    # Remove old attempts outside the window
    attempts[:] = [attempt for attempt in attempts if now - attempt < window]
    
    if len(attempts) >= max_attempts:
        return False
    
    attempts.append(now)
    return True

def require_auth(f):
    """Decorator untuk memastikan user sudah login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_role(allowed_roles):
    """Decorator untuk memastikan user memiliki role yang tepat"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                return redirect(url_for('login'))
            
            user_role = session['user'].get('role')
            if user_role not in allowed_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_input(data, required_fields):
    """Validasi input data"""
    errors = []
    
    for field in required_fields:
        if field not in data or not data[field]:
            errors.append(f'{field} is required')
    
    return errors

def sanitize_input(data):
    """Sanitasi input untuk mencegah injection"""
    if isinstance(data, str):
        # Basic sanitization
        data = data.strip()
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';']
        for char in dangerous_chars:
            data = data.replace(char, '')
    
    return data

# CSRF Protection
def generate_csrf_token():
    """Generate CSRF token"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return token == session.get('csrf_token')

# Audit logging
def log_security_event(event_type, user_id, details):
    """Log security events untuk audit"""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {event_type} - User: {user_id} - Details: {details}"
    
    # Write to security log file
    with open('security_audit.log', 'a') as f:
        f.write(log_entry + '\n')

# Password policy
def validate_password_strength(password):
    """Validasi kekuatan password"""
    errors = []
    
    if len(password) < 8:
        errors.append('Password minimal 8 karakter')
    
    if not any(c.isupper() for c in password):
        errors.append('Password harus mengandung huruf besar')
    
    if not any(c.islower() for c in password):
        errors.append('Password harus mengandung huruf kecil')
    
    if not any(c.isdigit() for c in password):
        errors.append('Password harus mengandung angka')
    
    return errors