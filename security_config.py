"""
Security Configuration Module
Enhanced security settings and utilities for the Aircraft Maintenance System
"""

import os
import secrets
from datetime import timedelta

class SecurityConfig:
    """Security configuration class"""
    
    # Session Security
    SESSION_TIMEOUT = timedelta(hours=2)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Password Security
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_NUMBERS = True
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_HASH_ROUNDS = 100000
    
    # Account Lockout
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    
    # Rate Limiting
    RATE_LIMIT_STORAGE_URL = "memory://"
    DEFAULT_RATE_LIMITS = ["200 per day", "50 per hour"]
    LOGIN_RATE_LIMIT = "5 per minute"
    API_RATE_LIMIT = "100 per hour"
    
    # File Upload Security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    UPLOAD_FOLDER = 'uploads'
    
    # CSRF Protection
    WTF_CSRF_TIME_LIMIT = None
    WTF_CSRF_SSL_STRICT = True
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; "
            "font-src 'self' cdnjs.cloudflare.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        ),
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }
    
    # Audit Logging
    AUDIT_LOG_FILE = 'audit_log.json'
    AUDIT_LOG_MAX_ENTRIES = 10000
    SECURITY_LOG_FILE = 'security.log'
    
    # Encryption
    ENCRYPTION_ALGORITHM = 'AES-256-GCM'
    KEY_DERIVATION_ITERATIONS = 100000
    
    @staticmethod
    def generate_secret_key():
        """Generate a secure secret key"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_csrf_token():
        """Generate a secure CSRF token"""
        return secrets.token_urlsafe(16)
    
    @staticmethod
    def is_safe_url(target):
        """Check if URL is safe for redirect"""
        from urllib.parse import urlparse, urljoin
        from flask import request
        
        ref_url = urlparse(request.host_url)
        test_url = urlparse(urljoin(request.host_url, target))
        return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

class InputValidator:
    """Input validation utilities"""
    
    @staticmethod
    def validate_nik(nik):
        """Validate NIK format (3 digits)"""
        import re
        return bool(re.match(r'^\d{3}$', str(nik)))
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_date(date_string):
        """Validate date format (YYYY-MM-DD)"""
        from datetime import datetime
        try:
            datetime.strptime(date_string, '%Y-%m-%d')
            return True
        except ValueError:
            return False
    
    @staticmethod
    def sanitize_text(text, max_length=255):
        """Sanitize text input"""
        import re
        if not text:
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', str(text))
        return sanitized[:max_length]
    
    @staticmethod
    def validate_password_strength(password):
        """Validate password strength"""
        import re
        
        if len(password) < SecurityConfig.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {SecurityConfig.PASSWORD_MIN_LENGTH} characters long"
        
        if SecurityConfig.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if SecurityConfig.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if SecurityConfig.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if SecurityConfig.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is strong"

class SecurityLogger:
    """Security event logging utilities"""
    
    @staticmethod
    def setup_logging():
        """Setup security logging configuration"""
        import logging
        from logging.handlers import RotatingFileHandler
        
        # Create security logger
        security_logger = logging.getLogger('security')
        security_logger.setLevel(logging.INFO)
        
        # Create file handler with rotation
        file_handler = RotatingFileHandler(
            SecurityConfig.SECURITY_LOG_FILE,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        security_logger.addHandler(file_handler)
        
        return security_logger
    
    @staticmethod
    def log_security_event(event_type, user_id, details, ip_address, user_agent):
        """Log security events"""
        import json
        from datetime import datetime
        
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'details': details,
            'ip_address': ip_address,
            'user_agent': user_agent
        }
        
        logger = logging.getLogger('security')
        logger.info(json.dumps(event))

class EncryptionHelper:
    """Encryption utilities for sensitive data"""
    
    def __init__(self, key=None):
        from cryptography.fernet import Fernet
        self.key = key or Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
    
    def encrypt(self, data):
        """Encrypt data"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher_suite.encrypt(data)
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
        decrypted = self.cipher_suite.decrypt(encrypted_data)
        return decrypted.decode()
    
    def encrypt_json(self, data):
        """Encrypt JSON data"""
        import json
        json_string = json.dumps(data)
        return self.encrypt(json_string)
    
    def decrypt_json(self, encrypted_data):
        """Decrypt JSON data"""
        import json
        decrypted_string = self.decrypt(encrypted_data)
        return json.loads(decrypted_string)

# Security middleware
def apply_security_headers(app):
    """Apply security headers to all responses"""
    @app.after_request
    def set_security_headers(response):
        for header, value in SecurityConfig.SECURITY_HEADERS.items():
            response.headers[header] = value
        return response

def setup_csrf_protection(app):
    """Setup CSRF protection"""
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)
    return csrf

def setup_rate_limiting(app):
    """Setup rate limiting"""
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    limiter = Limiter(
        app,
        key_func=get_remote_address,
        default_limits=SecurityConfig.DEFAULT_RATE_LIMITS,
        storage_uri=SecurityConfig.RATE_LIMIT_STORAGE_URL
    )
    return limiter