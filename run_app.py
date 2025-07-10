#!/usr/bin/env python3
"""
Script untuk menjalankan aplikasi Aircraft Maintenance Work Sheet
"""
import os
import sys

def main():
    # Set environment variables
    os.environ['FLASK_APP'] = 'app.py'
    os.environ['FLASK_ENV'] = 'development'
    os.environ['FLASK_DEBUG'] = '1'
    
    print("🚀 Starting Aircraft Maintenance Work Sheet System...")
    print("📋 Flask Application")
    print("🌐 Server akan berjalan di: http://localhost:5000")
    print("👥 Demo Accounts:")
    print("   Admin: 001 / 123")
    print("   Mechanic: 002 / 123") 
    print("   Quality Inspector: 003 / 123")
    print("   Quality Verifier: 004 / 123")
    print("   Super Admin: 005 / 123")
    print("-" * 50)
    
    # Import dan jalankan Flask app
    try:
        from app_secure import app  # Gunakan versi secure
        app.run(debug=True, host='0.0.0.0', port=5000)
    except ImportError as e:
        print(f"❌ Error importing Flask app: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()