#!/usr/bin/env python3
"""
Secure Application Runner
Runs the secure version of the Aircraft Maintenance System
"""

import os
import sys
import logging
from app_secure import app

def setup_environment():
    """Setup secure environment variables"""
    
    # Generate secure secret key if not set
    if not os.environ.get('SECRET_KEY'):
        import secrets
        os.environ['SECRET_KEY'] = secrets.token_urlsafe(32)
        print("Generated new SECRET_KEY for this session")
    
    # Setup encryption key if not set
    if not os.environ.get('ENCRYPTION_KEY'):
        from cryptography.fernet import Fernet
        os.environ['ENCRYPTION_KEY'] = Fernet.generate_key().decode()
        print("Generated new ENCRYPTION_KEY for this session")
    
    # Set secure defaults
    os.environ.setdefault('FLASK_ENV', 'production')
    os.environ.setdefault('FLASK_DEBUG', 'False')

def check_security_requirements():
    """Check if all security requirements are met"""
    
    try:
        # Check required packages
        import flask_limiter
        import flask_wtf
        import cryptography
        print("✓ All security packages are installed")
        
        # Check file permissions
        sensitive_files = ['users_data.json', 'worksheet_data.json', 'audit_log.json']
        for file in sensitive_files:
            if os.path.exists(file):
                stat = os.stat(file)
                if stat.st_mode & 0o077:
                    print(f"⚠ Warning: {file} has overly permissive permissions")
        
        return True
        
    except ImportError as e:
        print(f"✗ Missing security package: {e}")
        print("Please install: pip install -r requirements_secure.txt")
        return False

def main():
    """Main application entry point"""
    
    print("🔒 Starting Aircraft Maintenance System (Secure Version)")
    print("=" * 60)
    
    # Setup environment
    setup_environment()
    
    # Check security requirements
    if not check_security_requirements():
        sys.exit(1)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("\n🔐 Security Features Enabled:")
    print("  • Enhanced password hashing (PBKDF2)")
    print("  • Account lockout protection")
    print("  • Rate limiting")
    print("  • CSRF protection")
    print("  • Security headers")
    print("  • Audit logging")
    print("  • Input validation & sanitization")
    print("  • Session security")
    print("  • Data encryption")
    
    print("\n👥 Default User Accounts:")
    print("  • Admin (001/123) - Create MWS, Prepared By")
    print("  • Mechanic (002/123) - Fill MAN/Hours/TECH")
    print("  • Quality Inspector (003/123) - Inspection")
    print("  • Quality CUDR (004/123) - Verified By")
    print("  • Super Admin (005/123) - Approved By")
    
    print(f"\n🌐 Application will be available at:")
    print(f"  • HTTPS: https://localhost:5000")
    print(f"  • HTTP: http://localhost:5000 (redirects to HTTPS)")
    
    print("\n⚠ Security Notes:")
    print("  • Account locks after 5 failed login attempts")
    print("  • Sessions expire after 2 hours of inactivity")
    print("  • All actions are logged for audit purposes")
    print("  • Rate limiting is enforced on all endpoints")
    
    print("\n" + "=" * 60)
    print("🚀 Starting secure server...")
    
    try:
        # Run with SSL context for HTTPS
        app.run(
            debug=False,
            host='0.0.0.0',
            port=5000,
            ssl_context='adhoc',  # Self-signed certificate for development
            threaded=True
        )
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        print("\nTrying without SSL...")
        app.run(
            debug=False,
            host='0.0.0.0',
            port=5000,
            threaded=True
        )

if __name__ == '__main__':
    main()