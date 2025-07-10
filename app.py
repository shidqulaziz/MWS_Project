# type: ignore
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash 
import json
import os
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'maintenance_worksheet_secret_key_2024'

# Data storage (in production, use a proper database)
DATA_FILE = 'worksheet_data.json'
USERS_FILE = 'users_data.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return get_default_users()

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def get_default_users():
    # Data dummy users dengan NIK 3 digit dan password sederhana
    users = {
        '001': {
            'nik': '001',
            'name': 'Ahmad Wijaya',
            'password': hash_password('123'),
            'role': 'admin',
            'position': 'Admin (A)',
            'description': 'Pengguna A - Membuat MWS dan Prepared By'
        },
        '002': {
            'nik': '002',
            'name': 'Budi Santoso',
            'password': hash_password('123'),
            'role': 'mechanic',
            'position': 'Mekanik (U1)',
            'description': 'User 1 - Mengisi MAN, Hours, TECH dan Start/Finish Date'
        },
        '003': {
            'nik': '003',
            'name': 'Sari Indah',
            'password': hash_password('123'),
            'role': 'quality1',
            'position': 'Quality Inspector (U2)',
            'description': 'User 2 - Inspeksi setiap langkah kerja'
        },
        '004': {
            'nik': '004',
            'name': 'Dewi Lestari',
            'password': hash_password('123'),
            'role': 'quality2',
            'position': 'Quality CUDR (U3)',
            'description': 'User 3 - Verified By'
        },
        '005': {
            'nik': '005',
            'name': 'Eko Prasetyo',
            'password': hash_password('123'),
            'role': 'superadmin',
            'position': 'Super Admin (S.A)',
            'description': 'Super Admin - Approved By'
        }
    }
    save_users(users)
    return users

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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

@app.route('/')
def index():
    data = load_data()
    return render_template('index.html', parts=data['parts'])

@app.route('/login')
def login():
    role = request.args.get('role', '')
    return render_template('login.html', selected_role=role)

@app.route('/login', methods=['POST'])
def login_post():
    nik = request.form.get('nik')
    password = request.form.get('password')
    
    users = load_users()
    
    if nik in users:
        user = users[nik]
        if user['password'] == hash_password(password):
            session['user'] = {
                'nik': user['nik'],
                'name': user['name'],
                'role': user['role'],
                'position': user['position'],
                'description': user['description']
            }
            return redirect(url_for('role_dashboard'))
    
    flash('NIK atau password salah!', 'error')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    return redirect(url_for('role_dashboard'))

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    
    # Check if user has admin role
    if user['role'] != 'admin':
        flash('Akses ditolak! Anda tidak memiliki izin untuk mengakses halaman ini.', 'error')
        return redirect(url_for('role_dashboard'))
    
    data = load_data()
    users = load_users()
    
    # Admin can see all parts
    user_parts = data['parts']
    
    return render_template('admin_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/mechanic-dashboard')
def mechanic_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    
    # Check if user has mechanic role
    if user['role'] != 'mechanic':
        flash('Akses ditolak! Anda tidak memiliki izin untuk mengakses halaman ini.', 'error')
        return redirect(url_for('role_dashboard'))
    
    data = load_data()
    users = load_users()
    
    # Mechanic can only see assigned parts
    user_parts = {k: v for k, v in data['parts'].items() if v['assignedTo'] == user['nik']}
    
    return render_template('mechanic_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/quality1-dashboard')
def quality1_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    
    # Check if user has quality1 role
    if user['role'] != 'quality1':
        flash('Akses ditolak! Anda tidak memiliki izin untuk mengakses halaman ini.', 'error')
        return redirect(url_for('role_dashboard'))
    
    data = load_data()
    users = load_users()
    
    # Quality Inspector can see all parts for inspection
    user_parts = data['parts']
    
    return render_template('quality1_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/quality2-dashboard')
def quality2_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    
    # Check if user has quality2 role
    if user['role'] != 'quality2':
        flash('Akses ditolak! Anda tidak memiliki izin untuk mengakses halaman ini.', 'error')
        return redirect(url_for('role_dashboard'))
    
    data = load_data()
    users = load_users()
    
    # Quality CUDR can see all parts for verification
    user_parts = data['parts']
    
    return render_template('quality2_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/superadmin-dashboard')
def superadmin_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    
    # Check if user has superadmin role
    if user['role'] != 'superadmin':
        flash('Akses ditolak! Anda tidak memiliki izin untuk mengakses halaman ini.', 'error')
        return redirect(url_for('role_dashboard'))
    
    data = load_data()
    users = load_users()
    
    # Super Admin can see all parts and manage everything
    user_parts = data['parts']
    
    return render_template('superadmin_dashboard.html', user=user, parts=user_parts, users=users)

@app.route('/role-dashboard')
def role_dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    role = user['role']
    
    # Redirect to appropriate dashboard based on role
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
        flash('Role tidak dikenali!', 'error')
        return redirect(url_for('logout'))

@app.route('/mws/<part_id>')
def mws_detail(part_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = session['user']
    data = load_data()
    users = load_users()
    
    if part_id not in data['parts']:
        flash('MWS tidak ditemukan!', 'error')
        return redirect(url_for('dashboard'))
    
    part = data['parts'][part_id]
    return render_template('mws_detail.html', user=user, part=part, part_id=part_id, users=users)

@app.route('/create_mws')
def create_mws():
    if 'user' not in session or session['user']['role'] != 'admin':
        flash('Hanya Admin yang dapat membuat MWS baru!', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('create_mws.html', user=session['user'])

@app.route('/create_mws', methods=['POST'])
def create_mws_post():
    if 'user' not in session or session['user']['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = load_data()
    
    # Generate new part ID
    part_count = len(data['parts']) + 1
    part_id = f"MWS-{part_count:03d}"
    
    # Create new MWS
    new_mws = {
        'partNumber': request.json.get('partNumber'),
        'serialNumber': request.json.get('serialNumber'),
        'description': request.json.get('description'),
        'customer': request.json.get('customer'),
        'acType': request.json.get('acType'),
        'wbsNo': request.json.get('wbsNo'),
        'worksheetNo': request.json.get('worksheetNo'),
        'iwoNo': request.json.get('iwoNo'),
        'shopArea': request.json.get('shopArea'),
        'revision': request.json.get('revision', '1'),
        'status': 'pending',
        'currentStep': 0,
        'assignedTo': '',
        'startDate': '',
        'finishDate': '',
        'targetDate': request.json.get('targetDate'),
        'preparedBy': '',
        'preparedDate': '',
        'approvedBy': '',
        'approvedDate': '',
        'verifiedBy': '',
        'verifiedDate': '',
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
    
    return jsonify({'success': True, 'partId': part_id})

@app.route('/update_step_field', methods=['POST'])
def update_step_field():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = session['user']
    part_id = request.json.get('partId')
    step_no = request.json.get('stepNo')
    field = request.json.get('field')
    value = request.json.get('value')
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    part = data['parts'][part_id]
    step = next((s for s in part['steps'] if s['no'] == step_no), None)
    
    if not step:
        return jsonify({'error': 'Step not found'}), 404
    
    # Check permissions
    if field in ['man', 'hours', 'tech'] and user['role'] != 'mechanic':
        return jsonify({'error': 'Only mechanic can update MAN, Hours, TECH'}), 403
    
    if field == 'insp' and user['role'] != 'quality1':
        return jsonify({'error': 'Only Quality Inspector can update INSP'}), 403
    
    step[field] = value
    save_data(data)
    
    return jsonify({'success': True})

@app.route('/update_step_status', methods=['POST'])
def update_step_status():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = session['user']
    part_id = request.json.get('partId')
    step_no = request.json.get('stepNo')
    status = request.json.get('status')
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    part = data['parts'][part_id]
    step = next((s for s in part['steps'] if s['no'] == step_no), None)
    
    if not step:
        return jsonify({'error': 'Step not found'}), 404
    
    # Update step status
    step['status'] = status
    if status == 'completed':
        step['completedBy'] = user['nik']
        step['completedDate'] = datetime.now().strftime('%Y-%m-%d')
        
        # Update part current step
        if step_no > part['currentStep']:
            part['currentStep'] = step_no
            
        # Check if all steps completed
        completed_steps = sum(1 for s in part['steps'] if s['status'] == 'completed')
        if completed_steps == len(part['steps']):
            part['status'] = 'completed'
        elif completed_steps > 0:
            part['status'] = 'in_progress'
    
    save_data(data)
    return jsonify({'success': True})

@app.route('/assign_part', methods=['POST'])
def assign_part():
    if 'user' not in session or session['user']['role'] not in ['admin', 'superadmin']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    part_id = request.json.get('partId')
    assigned_to = request.json.get('assignedTo')
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    data['parts'][part_id]['assignedTo'] = assigned_to
    if not data['parts'][part_id]['startDate']:
        data['parts'][part_id]['startDate'] = datetime.now().strftime('%Y-%m-%d')
    
    save_data(data)
    return jsonify({'success': True})

@app.route('/update_dates', methods=['POST'])
def update_dates():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = session['user']
    part_id = request.json.get('partId')
    field = request.json.get('field')
    value = request.json.get('value')
    
    # Only mechanic can update start and finish dates
    if user['role'] != 'mechanic':
        return jsonify({'error': 'Only mechanic can update dates'}), 403
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    data['parts'][part_id][field] = value
    save_data(data)
    
    return jsonify({'success': True})

@app.route('/sign_document', methods=['POST'])
def sign_document():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 403
    
    user = session['user']
    part_id = request.json.get('partId')
    sign_type = request.json.get('type')
    
    data = load_data()
    
    if part_id not in data['parts']:
        return jsonify({'error': 'Part not found'}), 404
    
    part = data['parts'][part_id]
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    # Check permissions and sign
    if sign_type == 'prepared' and user['role'] == 'admin':
        part['preparedBy'] = user['nik']
        part['preparedDate'] = current_date
    elif sign_type == 'approved' and user['role'] == 'superadmin':
        part['approvedBy'] = user['nik']
        part['approvedDate'] = current_date
    elif sign_type == 'verified' and user['role'] == 'quality2':
        part['verifiedBy'] = user['nik']
        part['verifiedDate'] = current_date
    else:
        return jsonify({'error': 'Unauthorized for this signature type'}), 403
    
    save_data(data)
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)