# ============================================================
# DFIR Journal - Master Registrar API
# Flask + SQLite backend
# ============================================================

import sqlite3
import uuid
import hashlib
import json
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, session, g

app = Flask(__name__, static_folder='web', static_url_path='')
app.secret_key = 'CHANGE_THIS_IN_PRODUCTION'

DB_PATH = 'database/master.db'
SCHEMA_PATH = 'database/schema.sql'

# ============================================================
# DATABASE
# ============================================================

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with open(SCHEMA_PATH, 'r') as f:
            db.executescript(f.read())
        db.commit()
        # Create default master admin if none exists
        existing = db.execute('SELECT * FROM MasterUsers LIMIT 1').fetchone()
        if not existing:
            uid = str(uuid.uuid4())
            pwd_hash = hashlib.sha256('admin'.encode()).hexdigest()
            db.execute('''
                INSERT INTO MasterUsers (MasterUserId, DisplayName, Email, PasswordHash, Role)
                VALUES (?, ?, ?, ?, ?)
            ''', (uid, 'Master Admin', 'admin@dfir.local', pwd_hash, 'MasterAdmin'))
            db.commit()
            print(f'[INIT] Default admin created. Email: admin@dfir.local / Password: admin')
            print(f'[INIT] CHANGE THE PASSWORD IMMEDIATELY.')

# ============================================================
# AUDIT
# ============================================================

def compute_hash(previous_hash, event_type, actor_id, target_id, description, timestamp):
    data = f'{previous_hash}|{event_type}|{actor_id}|{target_id}|{description}|{timestamp}'
    return hashlib.sha256(data.encode()).hexdigest()

def write_audit(db, event_type, actor_id, actor_type, target_type, target_id, description):
    audit_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    last = db.execute('SELECT EntryHash FROM AuditLog ORDER BY CreatedAt DESC LIMIT 1').fetchone()
    previous_hash = last['EntryHash'] if last else 'GENESIS'
    entry_hash = compute_hash(previous_hash, event_type, actor_id, str(target_id), description, now)
    db.execute('''
        INSERT INTO AuditLog
            (AuditId, EventType, ActorId, ActorType, TargetType, TargetId, Description, PreviousHash, EntryHash, CreatedAt)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (audit_id, event_type, actor_id, actor_type, target_type, target_id, description, previous_hash, entry_hash, now))

# ============================================================
# AUTH
# ============================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    db = get_db()
    user = db.execute(
        'SELECT * FROM MasterUsers WHERE Email=? AND PasswordHash=? AND Status="Active"',
        (email, pwd_hash)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Invalid credentials or account inactive'}), 401
    session['user_id'] = user['MasterUserId']
    session['role'] = user['Role']
    write_audit(db, 'LOGIN', user['MasterUserId'], 'MasterUser', 'MasterUser', user['MasterUserId'], f'Login: {email}')
    db.commit()
    return jsonify({'message': 'Login successful', 'role': user['Role'], 'name': user['DisplayName']})

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    db = get_db()
    user = db.execute('SELECT MasterUserId, DisplayName, Email, Role, Status FROM MasterUsers WHERE MasterUserId=?',
                      (session['user_id'],)).fetchone()
    return jsonify(dict(user))

# ============================================================
# DOMAINS
# ============================================================

@app.route('/api/domains', methods=['GET'])
@login_required
def list_domains():
    db = get_db()
    rows = db.execute('SELECT * FROM Domains ORDER BY CreatedAt DESC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/domains', methods=['POST'])
@login_required
def create_domain():
    data = request.get_json()
    db = get_db()
    domain_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute('''
        INSERT INTO Domains (DomainId, DomainName, OrgName, ContactName, ContactEmail, Status, CreatedAt, UpdatedAt)
        VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)
    ''', (domain_id, data['DomainName'], data['OrgName'], data['ContactName'], data['ContactEmail'], now, now))
    write_audit(db, 'DOMAIN_CREATED', session['user_id'], 'MasterUser', 'Domain', domain_id, f"Domain created: {data['DomainName']}")
    db.commit()
    return jsonify({'message': 'Domain created', 'DomainId': domain_id}), 201

@app.route('/api/domains/<domain_id>/status', methods=['POST'])
@login_required
def update_domain_status(domain_id):
    data = request.get_json()
    new_status = data.get('Status')
    if new_status not in ('Active', 'Suspended', 'Revoked'):
        return jsonify({'error': 'Invalid status'}), 400
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    db.execute('UPDATE Domains SET Status=?, UpdatedAt=? WHERE DomainId=?', (new_status, now, domain_id))
    if new_status == 'Revoked':
        rev_id = str(uuid.uuid4())
        db.execute('''
            INSERT INTO RevocationRecords (RevocationId, TargetType, TargetId, Reason, IssuedByUserId)
            VALUES (?, 'Domain', ?, ?, ?)
        ''', (rev_id, domain_id, data.get('Reason', 'No reason given'), session['user_id']))
    write_audit(db, f'DOMAIN_STATUS_{new_status.upper()}', session['user_id'], 'MasterUser', 'Domain', domain_id, f'Domain status set to {new_status}')
    db.commit()
    return jsonify({'message': f'Domain status updated to {new_status}'})

# ============================================================
# REGISTRATION PACKETS
# ============================================================

@app.route('/api/packets', methods=['GET'])
@login_required
def list_packets():
    db = get_db()
    rows = db.execute('SELECT * FROM DomainRegistrationPackets ORDER BY SubmittedAt DESC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/packets/<packet_id>/decision', methods=['POST'])
@login_required
def decide_packet(packet_id):
    data = request.get_json()
    decision = data.get('Decision')
    if decision not in ('Approved', 'Rejected'):
        return jsonify({'error': 'Decision must be Approved or Rejected'}), 400
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    db.execute('''
        UPDATE DomainRegistrationPackets
        SET Status=?, ProcessedAt=?, ProcessedBy=?, DecisionReason=?
        WHERE PacketId=?
    ''', (decision, now, session['user_id'], data.get('Reason', ''), packet_id))
    write_audit(db, f'PACKET_{decision.upper()}', session['user_id'], 'MasterUser', 'RegistrationPacket', packet_id, f'Packet {decision}')
    db.commit()
    return jsonify({'message': f'Packet {decision}'})

# ============================================================
# AUDIT LOG
# ============================================================

@app.route('/api/audit', methods=['GET'])
@login_required
def get_audit():
    db = get_db()
    rows = db.execute('SELECT * FROM AuditLog ORDER BY CreatedAt DESC LIMIT 200').fetchall()
    return jsonify([dict(r) for r in rows])

# ============================================================
# REVOCATIONS
# ============================================================

@app.route('/api/revocations', methods=['GET'])
@login_required
def list_revocations():
    db = get_db()
    rows = db.execute('SELECT * FROM RevocationRecords ORDER BY CreatedAt DESC').fetchall()
    return jsonify([dict(r) for r in rows])

# ============================================================
# SERVE GUI
# ============================================================

@app.route('/')
def index():
    return app.send_static_file('index.html')

# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    init_db()
    print('[START] Master Registrar running on http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=False)
