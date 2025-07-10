# type: ignore
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import json
import os
import secrets
import hashlib
import hmac
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
import re
from cryptography.fernet import Fernet

# Initialize Flask app with security configurations
app = Flask(__name__)

# Security Configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_urlsafe(32)),
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    WTF_CSRF_TIME_LIMIT=None,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file upload
)

# Initialize security extensions
csrf = CSRFProtect(app)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configure template folder structure
app.jinja_env.loader.searchpath = [
    'templates',
    'templates/shared',
    'templates/auth', 
    'templates/admin',
    'templates/mechanic',
    'templates/quality',
    'templates/mws'
]

# Data storage files
DATA_FILE = 'worksheet_data.json'
USERS_FILE = 'users_data.json'
AUDIT_FILE = 'audit_log.json'

# Encryption key for sensitive data
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY)

# Security Headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; font-src 'self' cdnjs.cloudflare.com; img-src 'self' data:;"
    return response

# Audit logging function
def log_audit(user_id, action, details, ip_address):
    """Log security-relevant events"""
    audit_entry = {
        'timestamp': datetime.now().isoformat(),
        'user_id': user_id,
        'action': action,
        'details': details,
        'ip_address': ip_address,
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    
    try:
        if os.path.exists(AUDIT_FILE):
            with open(AUDIT_FILE, 'r') as f:
                audit_log = json.load(f)
        else:
            audit_log = []
        
        audit_log.append(audit_entry)
        
        # Keep only last 1000 entries
        if len(audit_log) > 1000:
            audit_log = audit_log[-1000:]
        
        with open(AUDIT_FILE, 'w') as f:
            json.dump(audit_log, f, indent=2)
            
        logger.info(f"Audit: {action} by {user_id} from {ip_address}")
    except Exception as e:
        logger.error(f"Failed to log audit entry: {e}")

# Input validation and sanitization
def validate_input(data, field_type):
    """Validate and sanitize input data"""
    if field_type == 'nik':
        # NIK should be exactly 3 digits
        if not re.match(r'^\d{3}$', str(data)):
            return None
        return data
    
    elif field_type == 'password':
        # Password should be at least 3 characters (for demo)
        if len(str(data)) < 3:
            return None
        return data
    
    elif field_type == 'text':
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', str(data))
        return sanitized[:255]  # Limit length
    
    elif field_type == 'date':
        # Validate date format
        try:
            datetime.strptime(data, '%Y-%m-%d')
            return data
        except ValueError:
            return None
    
    return str(data)[:255]  # Default sanitization

# Enhanced password hashing
def hash_password(password):
    """Create secure password hash with salt"""
    salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}:{password_hash.hex()}"

def verify_password(password, hash_string):
    """Verify password against hash"""
    try:
        salt, stored_hash = hash_string.split(':')
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(stored_hash, password_hash.hex())
    except ValueError:
        # Fallback for old SHA-256 hashes
        return hashlib.sha256(password.encode()).hexdigest() == hash_string

# Session security
def is_session_valid():
    """Check if current session is valid"""
    if 'user' not in session:
        return False
    
    # Check session timeout
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(hours=2):
            session.clear()
            return False
    
    session['last_activity'] = datetime.now().isoformat()
    return True

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_session_valid():
            flash('Session expired. Please login again.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Role-based access control decorator
def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not is_session_valid():
                return redirect(url_for('login'))
            
            user_role = session['user'].get('role')
            if user_role not in allowed_roles:
                log_audit(
                    session['user'].get('nik', 'unknown'),
                    'UNAUTHORIZED_ACCESS_ATTEMPT',
                    f"Attempted to access {request.endpoint} with role {user_role}",
                    request.remote_addr
                )
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('role_dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Data loading and saving with encryption for sensitive data
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return get_default_users()

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def get_default_users():
    """Create default users with secure password hashing"""
    users = {
        '001': {
            'nik': '001',
            'name': 'Ahmad Wijaya',
            'password': hash_password('123'),
            'role': 'admin',
            'position': 'Admin (A)',
            'description': 'Pengguna A - Membuat MWS dan Prepared By',
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        },
        '002': {
            'nik': '002',
            'name': 'Budi Santoso',
            'password': hash_password('123'),
            'role': 'mechanic',
            'position': 'Mekanik (U1)',
            'description': 'User 1 - Mengisi MAN, Hours, TECH dan Start/Finish Date',
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        },
        '003': {
            'nik': '003',
            'name': 'Sari Indah',
            'password': hash_password('123'),
            'role': 'quality1',
            'position': 'Quality Inspector (U2)',
            'description': 'User 2 - Inspeksi setiap langkah kerja',
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        },
        '004': {
            'nik': '004',
            'name': 'Dewi Lestari',
            'password': hash_password('123'),
            'role': 'quality2',
            'position': 'Quality CUDR (U3)',
            'description': 'User 3 - Verified By',
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        },
        '005': {
            'nik': '005',
            'name': 'Eko Prasetyo',
            'password': hash_password('123'),
            'role': 'superadmin',
            'position': 'Super Admin (S.A)',
            'description': 'Super Admin - Approved By',
            'created_at': datetime.now().isoformat(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None
        }
    }
    save_users(users)
    return users

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return get_default_data()

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def get_default_data():
    return {
        'parts': {
            'AOA-001': {
                'partNumber': 'AOA-001',
                'serialNumber': 'SN123456',
                'description': 'Angle of Attack Indicator',
                'customer': 'Garuda Indonesia',
                'acType': 'CN235',
                'wbsNo': 'A/S90-025CN235-90-99-99',
                'worksheetNo': 'IN-108',
                'iwoNo': 'Z501-00001',
                'shopArea': 'IN',
                'revision': '1',
                'status': 'in_progress',
                'currentStep': 3,
                'assignedTo': '002',
                'startDate': '2024-01-15',
                'finishDate': '',
                'targetDate': '2024-01-25',
                'preparedBy': '',
                'preparedDate': '',
                'approvedBy': '',
                'approvedDate': '',
                'verifiedBy': '',
                'verifiedDate': '',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'steps': [
                    {
                        'no': 1,
                        'description': 'Incoming Record\nA. Check PN and SN to be according with MWS then record actual\nPN: ........................ SN: ............................\nB. Check document attachment needed are completed.\nC. Visual inspection for completed.\nRecord the part not completely if any\nDESCRIPTION    PN    SN    QTY',
                        'status': 'completed',
                        'completedBy': '002',
                        'completedDate': '2024-01-15',
                        'man': 'A',
                        'hours': '',
                        'tech': '',
                        'insp': ''
                    },
                    {
                        'no': 2,
                        'description': 'Functional Test\nDo a Functional Test procedures ref. CMM,\nChapter 34-12-24, page 5.',
                        'status': 'completed',
                        'completedBy': '002',
                        'completedDate': '2024-01-16',
                        'man': 'A',
                        'hours': '',
                        'tech': '',
                        'insp': ''
                    },
                    {
                        'no': 3,
                        'description': 'Fault Isolation\nDo a Fault Isolation procedures ref. CMM,\nChapter 34-12-24, page 5.',
                        'status': 'in_progress',
                        'completedBy': '',
                        'completedDate': '',
                        'man': 'A',
                        'hours': '',
                        'tech': '',
                        'insp': ''
                    },
                    {
                        'no': 4,
                        'description': 'Disassembly\nDo a Disassembly procedures ref. CMM,\nChapter 34-12-24, page 13.',
                        'status': 'pending',
                        'completedBy': '',
                        'completedDate': '',
                        'man': 'A',
                        'hours': 'U1',
                        'tech': 'U1',
                        'insp': 'U2'
                    },
                    {
                        'no': 5,
                        'description': 'Cleaning\nDo a Cleaning procedures ref. CMM,\nChapter 34-12-24, page 16.',
                        'status': 'pending',
                        'completedBy': '',
                        'completedDate': '',
                        'man': 'A',
                        'hours': '',
                        'tech': '',
                        'insp': ''
                    },
                    {
                        'no': 6,
                        'description': 'Check\nDo a Check procedures ref. CMM,\nChapter 34-12-24, page 16.',
                        'status': 'pending',
                        'completedBy': '',
                        'completedDate': '',
                        'man': 'A',
                        'hours': '',
                        'tech': '',
                        'insp': ''
                    },
                    {
                        'no': 7,
                        'description': 'Assembly\nDo a Assembly procedures ref. CMM,\nChapter 34-12-24, page 17.',
                        'status': 'pending',
                        'completedBy': '',
                        'completedDate': '',
                        'man': 'A',
                        'hours': '',
                        'tech': '',
                        'insp': ''
                    },
                    {
                        'no': 8,
                        'description': 'Functional Test\nDo a Functional Test procedures ref. CMM,\nChapter 34-12-24, page 5.',
                        'status': 'pending',
                        'completedBy': '',
                        'completedDate': '',
                        'man': '',
                        'hours': '',
                        'tech': '',
                        'insp': ''
                    },
                    {
                        'no': 9,
                        'description': 'FOD Control\nA. Personnel who carry out the component are wearing the FOD bag and should not wear attributes indicated to be FOD.\nB. Ensure the component being maintained are free from FOD, dust, and oil spill.\nC. Cleaning up the documents, materials, standard parts, or consumable parts and send them to the proper place.',
                        'status': 'pending',
                        'completedBy': '',
                        'completedDate': '',
                        'man': 'A',
                        'hours': 'U1',
                        'tech': 'U1',
                        'insp': 'U2'
                    },
                    {
                        'no': 10,
                        'description': 'Final Inspection\nA. Check PN and SN of Angle Of Attack Indicator to be according with MWS.\nB. Check actual test Angle Of Attack Indicator for functional test and good external condition.\nC. Check operating to completed and properly stamped.\nD. Produce Serviceable Tag Release external Angle Of Attack Indicator.',
                        'status': 'pending',
                        'completedBy': '',
                        'completedDate': '',
                        'man': 'A',
                        'hours': '',
                        'tech': '',
                        'insp': ''
                    }
                ]
            }
        }
    }

# Routes
@app.route('/')
def index():
    data = load_data()
    return render_template('shared/index.html', parts=data['parts'])

@app.route('/login')
@limiter.limit("10 per minute")
def login():
    role = request.args.get('role', '')
    return render_template('auth/login.html', selected_role=role)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login_post():
    nik = validate_input(request.form.get('nik'), 'nik')
    password = validate_input(request.form.get('password'), 'password')
    
    if not nik or not password:
        log_audit('unknown', 'INVALID_LOGIN_ATTEMPT', 'Invalid input format', request.remote_addr)
        flash('Invalid input format!', 'error')
        return redirect(url_for('login'))
    
    users = load_users()
    
    if nik in users:
        user = users[nik]
        
        # Check if account is locked
        if user.get('locked_until'):
            locked_until = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < locked_until:
                log_audit(nik, 'LOGIN_ATTEMPT_LOCKED_ACCOUNT', '', request.remote_addr)
                flash('Account is temporarily locked. Please try again later.', 'error')
                return redirect(url_for('login'))
            else:
                # Unlock account
                user['locked_until'] = None
                user['failed_attempts'] = 0
        
        if verify_password(password, user['password']):
            # Successful login
            session.permanent = True
            session['user'] = {
                'nik': user['nik'],
                'name': user['name'],
                'role': user['role'],
                'position': user['position'],
                'description': user['description']
            }
            session['last_activity'] = datetime.now().isoformat()
            
            # Reset failed attempts and update last login
            user['failed_attempts'] = 0
            user['locked_until'] = None
            user['last_login'] = datetime.now().isoformat()
            save_users(users)
            
            log_audit(nik, 'SUCCESSFUL_LOGIN', '', request.remote_addr)
            return redirect(url_for('role_dashboard'))
        else:
            # Failed login
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            
            # Lock account after 5 failed attempts
            if user['failed_attempts'] >= 5:
                user['locked_until'] = (datetime.now() + timedelta(minutes=15)).isoformat()
                log_audit(nik, 'ACCOUNT_LOCKED', f"Too many failed attempts", request.remote_addr)
                flash('Account locked due to too many failed attempts. Try again in 15 minutes.', 'error')
            else:
                log_audit(nik, 'FAILED_LOGIN_ATTEMPT', f"Attempt {user['failed_attempts']}", request.remote_addr)
                flash(f'Invalid credentials! {5 - user["failed_attempts"]} attempts remaining.', 'error')
            
            save_users(users)
    else:
        log_audit(nik, 'LOGIN_ATTEMPT_UNKNOWN_USER', '', request.remote_addr)
        flash('Invalid credentials!', 'error')
    
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    user_nik = session.get('user', {}).get('nik', 'unknown')
    log_audit(user_nik, 'LOGOUT', '', request.remote_addr)
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('role_dashboard'))

@app.route('/admin-dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    user = session['user']
    data = load_data()
    users = load_users()
    user_parts = data['parts']
    
    log_audit(user['nik'], 'ACCESS_ADMIN_DASHBOARD', '', request.remote_addr)
    return render_template('admin/admin_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/mechanic-dashboard')
@login_required
@role_required(['mechanic'])
def mechanic_dashboard():
    user = session['user']
    data = load_data()
    users = load_users()
    user_parts = {k: v for k, v in data['parts'].items() if v['assignedTo'] == user['nik']}
    
    log_audit(user['nik'], 'ACCESS_MECHANIC_DASHBOARD', '', request.remote_addr)
    return render_template('mechanic/mechanic_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/quality1-dashboard')
@login_required
@role_required(['quality1'])
def quality1_dashboard():
    user = session['user']
    data = load_data()
    users = load_users()
    user_parts = data['parts']
    
    log_audit(user['nik'], 'ACCESS_QUALITY1_DASHBOARD', '', request.remote_addr)
    return render_template('quality1_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/quality2-dashboard')
@login_required
@role_required(['quality2'])
def quality2_dashboard():
    user = session['user']
    data = load_data()
    users = load_users()
    user_parts = data['parts']
    
    log_audit(user['nik'], 'ACCESS_QUALITY2_DASHBOARD', '', request.remote_addr)
    return render_template('quality2_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/superadmin-dashboard')
@login_required
@role_required(['superadmin'])
def superadmin_dashboard():
    user = session['user']
    data = load_data()
    users = load_users()
    user_parts = data['parts']
    
    log_audit(user['nik'], 'ACCESS_SUPERADMIN_DASHBOARD', '', request.remote_addr)
    return render_template('admin/superadmin_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/role-dashboard')
@login_required
def role_dashboard():
    user = session['user']
    role = user['role']
    
    if role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'mechanic':
        return redirect(url_for('mechanic_dashboard'))
    elif role == 'quality1':
        return redirect(url_for('quality1_dashboard'))
    elif role == 'quality2':
        return redirect(url_for('quality2_dashboard'))
    elif role == 'superadmin':
        return redirect(url_for('superadmin_dashboard'))
    else:
        log_audit(user['nik'], 'UNKNOWN_ROLE_ACCESS', f"Role: {role}", request.remote_addr)
        flash('Unknown role!', 'error')
        return redirect(url_for('logout'))

@app.route('/mws/<part_id>')
@login_required
def mws_detail(part_id):
    user = session['user']
    data = load_data()
    users = load_users()
    
    # Validate part_id
    part_id = validate_input(part_id, 'text')
    if not part_id or part_id not in data['parts']:
        log_audit(user['nik'], 'INVALID_MWS_ACCESS', f"Part ID: {part_id}", request.remote_addr)
        flash('MWS not found!', 'error')
        return redirect(url_for('dashboard'))
    
    part = data['parts'][part_id]
    log_audit(user['nik'], 'ACCESS_MWS_DETAIL', f"Part: {part_id}", request.remote_addr)
    return render_template('mws/mws_detail.html', user=user, part=part, part_id=part_id, users=users)

@app.route('/create_mws')
@login_required
@role_required(['admin'])
def create_mws():
    return render_template('admin/create_mws.html', user=session['user'])

@app.route('/create_mws', methods=['POST'])
@login_required
@role_required(['admin'])
@limiter.limit("10 per hour")
def create_mws_post():
    user = session['user']
    data = load_data()
    
    # Validate and sanitize input
    part_number = validate_input(request.json.get('partNumber'), 'text')
    serial_number = validate_input(request.json.get('serialNumber'), 'text')
    description = validate_input(request.json.get('description'), 'text')
    customer = validate_input(request.json.get('customer'), 'text')
    ac_type = validate_input(request.json.get('acType'), 'text')
    wbs_no = validate_input(request.json.get('wbsNo'), 'text')
    worksheet_no = validate_input(request.json.get('worksheetNo'), 'text')
    iwo_no = validate_input(request.json.get('iwoNo'), 'text')
    shop_area = validate_input(request.json.get('shopArea'), 'text')
    revision = validate_input(request.json.get('revision', '1'), 'text')
    target_date = validate_input(request.json.get('targetDate'), 'date')
    
    if not all([part_number, serial_number, description, customer, ac_type, wbs_no, worksheet_no, iwo_no, shop_area, target_date]):
        log_audit(user['nik'], 'INVALID_MWS_CREATION', 'Missing required fields', request.remote_addr)
        return jsonify({'error': 'All fields are required and must be valid'}), 400
    
    # Generate new part ID
    part_count = len(data['parts']) + 1
    part_id = f"MWS-{part_count:03d}"
    
    # Create new MWS
    new_mws = {
        'partNumber': part_number,
        'serialNumber': serial_number,
        'description': description,
        'customer': customer,
        'acType': ac_type,
        'wbsNo': wbs_no,
        'worksheetNo': worksheet_no,
        'iwoNo': iwo_no,
        'shopArea': shop_area,
        'revision': revision,
        'status': 'pending',
        'currentStep': 0,
        'assignedTo': '',
        'startDate': '',
        'finishDate': '',
        'targetDate': target_date,
        'preparedBy': '',
        'preparedDate': '',
        'approvedBy': '',
        'approvedDate': '',
        'verifiedBy': '',
        'verifiedDate': '',
        'created_at': datetime.now().isoformat(),
        'created_by': user['nik'],
        'updated_at': datetime.now().isoformat(),
        'steps': []
    }
    
    # Add default steps
    default_steps = [
        'Incoming Record',
        'Functional Test',
        'Fault Isolation',
        'Disassembly',
        'Cleaning',
        'Check',
        'Assembly',
        'Functional Test',
        'FOD Control',
        'Final Inspection'
    ]
    
    for i, step_desc in enumerate(default_steps, 1):
        new_mws['steps'].append({
            'no': i,
            'description': step_desc,
            'status': 'pending',
            'completedBy': '',
            'completedDate': '',
            'man': '',
            'hours': '',
            'tech': '',
            'insp': ''
        })
    
    data['parts'][part_id] = new_mws
    save_data(data)
    
    log_audit(user['nik'], 'MWS_CREATED', f"Part ID: {part_id}, Part Number: {part_number}", request.remote_addr)
    return jsonify({'success': True, 'partId': part_id})

@app.route('/update_step_field', methods=['POST'])
@login_required
@limiter.limit("100 per hour")
def update_step_field():
    user = session['user']
    part_id = validate_input(request.json.get('partId'), 'text')
    step_no = request.json.get('stepNo')
    field = validate_input(request.json.get('field'), 'text')
    value = validate_input(request.json.get('value'), 'text')
    
    if not all([part_id, step_no, field]) or field not in ['man', 'hours', 'tech', 'insp']:
        return jsonify({'error': 'Invalid parameters'}), 400
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    part = data['parts'][part_id]
    step = next((s for s in part['steps'] if s['no'] == step_no), None)
    
    if not step:
        return jsonify({'error': 'Step not found'}), 404
    
    # Check permissions
    if field in ['man', 'hours', 'tech'] and user['role'] != 'mechanic':
        log_audit(user['nik'], 'UNAUTHORIZED_STEP_UPDATE', f"Field: {field}, Part: {part_id}", request.remote_addr)
        return jsonify({'error': 'Only mechanic can update MAN, Hours, TECH'}), 403
    
    if field == 'insp' and user['role'] != 'quality1':
        log_audit(user['nik'], 'UNAUTHORIZED_STEP_UPDATE', f"Field: {field}, Part: {part_id}", request.remote_addr)
        return jsonify({'error': 'Only Quality Inspector can update INSP'}), 403
    
    old_value = step.get(field, '')
    step[field] = value
    part['updated_at'] = datetime.now().isoformat()
    save_data(data)
    
    log_audit(user['nik'], 'STEP_FIELD_UPDATED', f"Part: {part_id}, Step: {step_no}, Field: {field}, Old: {old_value}, New: {value}", request.remote_addr)
    return jsonify({'success': True})

@app.route('/update_step_status', methods=['POST'])
@login_required
@limiter.limit("50 per hour")
def update_step_status():
    user = session['user']
    part_id = validate_input(request.json.get('partId'), 'text')
    step_no = request.json.get('stepNo')
    status = validate_input(request.json.get('status'), 'text')
    
    if not all([part_id, step_no, status]) or status not in ['pending', 'in_progress', 'completed']:
        return jsonify({'error': 'Invalid parameters'}), 400
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    part = data['parts'][part_id]
    step = next((s for s in part['steps'] if s['no'] == step_no), None)
    
    if not step:
        return jsonify({'error': 'Step not found'}), 404
    
    old_status = step['status']
    step['status'] = status
    
    if status == 'completed':
        step['completedBy'] = user['nik']
        step['completedDate'] = datetime.now().strftime('%Y-%m-%d')
        
        if step_no > part['currentStep']:
            part['currentStep'] = step_no
            
        completed_steps = sum(1 for s in part['steps'] if s['status'] == 'completed')
        if completed_steps == len(part['steps']):
            part['status'] = 'completed'
        elif completed_steps > 0:
            part['status'] = 'in_progress'
    
    part['updated_at'] = datetime.now().isoformat()
    save_data(data)
    
    log_audit(user['nik'], 'STEP_STATUS_UPDATED', f"Part: {part_id}, Step: {step_no}, Old: {old_status}, New: {status}", request.remote_addr)
    return jsonify({'success': True})

@app.route('/assign_part', methods=['POST'])
@login_required
@role_required(['admin', 'superadmin'])
@limiter.limit("20 per hour")
def assign_part():
    user = session['user']
    part_id = validate_input(request.json.get('partId'), 'text')
    assigned_to = validate_input(request.json.get('assignedTo'), 'nik')
    
    if not all([part_id, assigned_to]):
        return jsonify({'error': 'Invalid parameters'}), 400
    
    data = load_data()
    users = load_users()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    if assigned_to not in users or users[assigned_to]['role'] != 'mechanic':
        return jsonify({'error': 'Invalid mechanic'}), 400
    
    old_assigned = data['parts'][part_id].get('assignedTo', '')
    data['parts'][part_id]['assignedTo'] = assigned_to
    data['parts'][part_id]['updated_at'] = datetime.now().isoformat()
    
    if not data['parts'][part_id]['startDate']:
        data['parts'][part_id]['startDate'] = datetime.now().strftime('%Y-%m-%d')
    
    save_data(data)
    
    log_audit(user['nik'], 'PART_ASSIGNED', f"Part: {part_id}, From: {old_assigned}, To: {assigned_to}", request.remote_addr)
    return jsonify({'success': True})

@app.route('/update_dates', methods=['POST'])
@login_required
@role_required(['mechanic'])
@limiter.limit("30 per hour")
def update_dates():
    user = session['user']
    part_id = validate_input(request.json.get('partId'), 'text')
    field = validate_input(request.json.get('field'), 'text')
    value = validate_input(request.json.get('value'), 'date')
    
    if not all([part_id, field, value]) or field not in ['startDate', 'finishDate']:
        return jsonify({'error': 'Invalid parameters'}), 400
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    old_value = data['parts'][part_id].get(field, '')
    data['parts'][part_id][field] = value
    data['parts'][part_id]['updated_at'] = datetime.now().isoformat()
    save_data(data)
    
    log_audit(user['nik'], 'DATE_UPDATED', f"Part: {part_id}, Field: {field}, Old: {old_value}, New: {value}", request.remote_addr)
    return jsonify({'success': True})

@app.route('/sign_document', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def sign_document():
    user = session['user']
    part_id = validate_input(request.json.get('partId'), 'text')
    sign_type = validate_input(request.json.get('type'), 'text')
    
    if not all([part_id, sign_type]) or sign_type not in ['prepared', 'approved', 'verified']:
        return jsonify({'error': 'Invalid parameters'}), 400
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    part = data['parts'][part_id]
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    # Check permissions and sign
    if sign_type == 'prepared' and user['role'] == 'admin':
        if part['preparedBy']:
            return jsonify({'error': 'Document already signed'}), 400
        part['preparedBy'] = user['nik']
        part['preparedDate'] = current_date
    elif sign_type == 'approved' and user['role'] == 'superadmin':
        if part['approvedBy']:
            return jsonify({'error': 'Document already signed'}), 400
        part['approvedBy'] = user['nik']
        part['approvedDate'] = current_date
    elif sign_type == 'verified' and user['role'] == 'quality2':
        if part['verifiedBy']:
            return jsonify({'error': 'Document already signed'}), 400
        part['verifiedBy'] = user['nik']
        part['verifiedDate'] = current_date
    else:
        log_audit(user['nik'], 'UNAUTHORIZED_SIGNATURE', f"Type: {sign_type}, Part: {part_id}", request.remote_addr)
        return jsonify({'error': 'Unauthorized for this signature type'}), 403
    
    part['updated_at'] = datetime.now().isoformat()
    save_data(data)
    
    log_audit(user['nik'], 'DOCUMENT_SIGNED', f"Type: {sign_type}, Part: {part_id}", request.remote_addr)
    return jsonify({'success': True})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('shared/error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('shared/error.html', error_code=403, error_message="Access forbidden"), 403

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('shared/error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('shared/error.html', error_code=429, error_message="Rate limit exceeded. Please try again later."), 429

if __name__ == '__main__':
    # Ensure secure configuration for production
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc')