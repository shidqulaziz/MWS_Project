# Enhanced Flask app dengan security improvements
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from security_config import *
import json
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Apply security configuration
app.config.update(
    SECRET_KEY=SecurityConfig.SECRET_KEY,
    SESSION_COOKIE_SECURE=SecurityConfig.SESSION_COOKIE_SECURE,
    SESSION_COOKIE_HTTPONLY=SecurityConfig.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=SecurityConfig.SESSION_COOKIE_SAMESITE,
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=SecurityConfig.PERMANENT_SESSION_LIFETIME)
)

# CSRF Protection untuk semua POST requests
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('csrf_token', None)
        if not token or token != request.form.get('csrf_token'):
            if request.is_json:
                return jsonify({'error': 'CSRF token missing or invalid'}), 403
            else:
                flash('Security error: Invalid request', 'error')
                return redirect(url_for('index'))

# Add CSRF token to all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)

# Enhanced login dengan rate limiting
@app.route('/login', methods=['POST'])
def login_post():
    nik = request.form.get('nik')
    password = request.form.get('password')
    client_ip = request.remote_addr
    
    # Rate limiting check
    if not rate_limit_check(client_ip):
        log_security_event('RATE_LIMIT_EXCEEDED', nik or 'unknown', f'IP: {client_ip}')
        flash('Terlalu banyak percobaan login. Coba lagi dalam 5 menit.', 'error')
        return redirect(url_for('login'))
    
    # Input validation
    if not nik or not password:
        log_security_event('LOGIN_INVALID_INPUT', nik or 'unknown', f'IP: {client_ip}')
        flash('NIK dan password harus diisi!', 'error')
        return redirect(url_for('login'))
    
    # Sanitize input
    nik = sanitize_input(nik)
    
    users = load_users()
    
    if nik in users:
        user = users[nik]
        if verify_password(password, user['password']):
            session.permanent = True
            session['user'] = {
                'nik': user['nik'],
                'name': user['name'],
                'role': user['role'],
                'position': user['position'],
                'description': user['description'],
                'login_time': datetime.now().isoformat()
            }
            
            log_security_event('LOGIN_SUCCESS', nik, f'IP: {client_ip}')
            return redirect(url_for('role_dashboard'))
    
    log_security_event('LOGIN_FAILED', nik or 'unknown', f'IP: {client_ip}')
    flash('NIK atau password salah!', 'error')
    return redirect(url_for('login'))

# Enhanced user creation dengan secure password
def create_secure_users():
    """Create users dengan password yang di-hash secara aman"""
    users = {
        '001': {
            'nik': '001',
            'name': 'Ahmad Wijaya',
            'password': secure_hash_password('Admin123!'),
            'role': 'admin',
            'position': 'Admin (A)',
            'description': 'Pengguna A - Membuat MWS dan Prepared By'
        },
        '002': {
            'nik': '002',
            'name': 'Budi Santoso',
            'password': secure_hash_password('Mechanic123!'),
            'role': 'mechanic',
            'position': 'Mekanik (U1)',
            'description': 'User 1 - Mengisi MAN, Hours, TECH dan Start/Finish Date'
        },
        '003': {
            'nik': '003',
            'name': 'Sari Indah',
            'password': secure_hash_password('Quality123!'),
            'role': 'quality1',
            'position': 'Quality Inspector (U2)',
            'description': 'User 2 - Inspeksi setiap langkah kerja'
        },
        '004': {
            'nik': '004',
            'name': 'Dewi Lestari',
            'password': secure_hash_password('Quality456!'),
            'role': 'quality2',
            'position': 'Quality CUDR (U3)',
            'description': 'User 3 - Verified By'
        },
        '005': {
            'nik': '005',
            'name': 'Eko Prasetyo',
            'password': secure_hash_password('SuperAdmin789!'),
            'role': 'superadmin',
            'position': 'Super Admin (S.A)',
            'description': 'Super Admin - Approved By'
        }
    }
    return users

# Protected routes dengan decorators
@app.route('/admin-dashboard')
@require_auth
@require_role(['admin'])
def admin_dashboard():
    user = session['user']
    data = load_data()
    users = load_users()
    user_parts = data['parts']
    
    log_security_event('ADMIN_DASHBOARD_ACCESS', user['nik'], 'Dashboard accessed')
    return render_template('admin/admin_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/update_step_field', methods=['POST'])
@require_auth
def update_step_field():
    user = session['user']
    
    # Validate input
    required_fields = ['partId', 'stepNo', 'field', 'value']
    errors = validate_input(request.json, required_fields)
    
    if errors:
        log_security_event('INVALID_INPUT', user['nik'], f'Errors: {errors}')
        return jsonify({'error': 'Invalid input', 'details': errors}), 400
    
    part_id = sanitize_input(request.json.get('partId'))
    step_no = request.json.get('stepNo')
    field = sanitize_input(request.json.get('field'))
    value = sanitize_input(request.json.get('value'))
    
    # Authorization check
    if field in ['man', 'hours', 'tech'] and user['role'] != 'mechanic':
        log_security_event('UNAUTHORIZED_ACCESS', user['nik'], f'Attempted to update {field}')
        return jsonify({'error': 'Only mechanic can update MAN, Hours, TECH'}), 403
    
    if field == 'insp' and user['role'] != 'quality1':
        log_security_event('UNAUTHORIZED_ACCESS', user['nik'], f'Attempted to update {field}')
        return jsonify({'error': 'Only Quality Inspector can update INSP'}), 403
    
    # Process update...
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    part = data['parts'][part_id]
    step = next((s for s in part['steps'] if s['no'] == step_no), None)
    
    if not step:
        return jsonify({'error': 'Step not found'}), 404
    
    step[field] = value
    save_data(data)
    
    log_security_event('STEP_FIELD_UPDATED', user['nik'], f'Part: {part_id}, Step: {step_no}, Field: {field}')
    return jsonify({'success': True})

# Session timeout check
@app.before_request
def check_session_timeout():
    if 'user' in session:
        login_time = session['user'].get('login_time')
        if login_time:
            login_datetime = datetime.fromisoformat(login_time)
            if datetime.now() - login_datetime > timedelta(seconds=SecurityConfig.PERMANENT_SESSION_LIFETIME):
                session.clear()
                flash('Session expired. Please login again.', 'info')
                return redirect(url_for('login'))

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.tailwindcss.com cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' cdn.tailwindcss.com cdnjs.cloudflare.com; font-src 'self' cdnjs.cloudflare.com"
    return response

if __name__ == '__main__':
    # Production settings
    app.run(debug=False, host='127.0.0.1', port=5000, ssl_context='adhoc')