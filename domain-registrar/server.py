# ============================================================
# DFIR Journal - Domain Registrar API
# Flask + SQLite backend - port 5001
# ============================================================

import sqlite3
import uuid
import hashlib
import json
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, request, jsonify, session, g

app = Flask(__name__, static_folder='web', static_url_path='')
app.secret_key = 'DOMAIN_CHANGE_THIS_IN_PRODUCTION'

DB_PATH = 'database/domain.db'
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
        existing = db.execute('SELECT * FROM Users LIMIT 1').fetchone()
        if not existing:
            uid = str(uuid.uuid4())
            pwd_hash = hashlib.sha256('admin'.encode()).hexdigest()
            db.execute('''
                INSERT INTO Users (UserId, DisplayName, Email, PasswordHash, Role)
                VALUES (?, ?, ?, ?, ?)
            ''', (uid, 'Domain Admin', 'admin@domain.local', pwd_hash, 'DomainAdmin'))
            db.commit()
            print('[INIT] Default domain admin created. Email: admin@domain.local / Password: admin')
            print('[INIT] CHANGE THE PASSWORD IMMEDIATELY.')

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

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') not in ('DomainAdmin', 'Supervisor'):
            return jsonify({'error': 'Insufficient privileges'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email','').strip().lower()
    pwd_hash = hashlib.sha256(data.get('password','').encode()).hexdigest()
    db = get_db()
    user = db.execute(
        'SELECT * FROM Users WHERE Email=? AND PasswordHash=? AND Status="Active"',
        (email, pwd_hash)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Invalid credentials or account inactive'}), 401
    session['user_id'] = user['UserId']
    session['role'] = user['Role']
    write_audit(db, 'LOGIN', user['UserId'], 'User', 'User', user['UserId'], f'Login: {email}')
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
    user = db.execute(
        'SELECT UserId, DisplayName, Email, Role, Status FROM Users WHERE UserId=?',
        (session['user_id'],)
    ).fetchone()
    return jsonify(dict(user))

# ============================================================
# DOMAIN IDENTITY
# ============================================================

@app.route('/api/identity', methods=['GET'])
@login_required
def get_identity():
    db = get_db()
    row = db.execute('SELECT * FROM DomainIdentity LIMIT 1').fetchone()
    return jsonify(dict(row) if row else {})

@app.route('/api/identity', methods=['POST'])
@login_required
@admin_required
def set_identity():
    data = request.get_json()
    db = get_db()
    existing = db.execute('SELECT * FROM DomainIdentity LIMIT 1').fetchone()
    now = datetime.now(timezone.utc).isoformat()
    if existing:
        db.execute('''UPDATE DomainIdentity SET DomainName=?, OrgName=?, ContactName=?, ContactEmail=?, UpdatedAt=?
                      WHERE DomainId=?''',
                   (data['DomainName'], data['OrgName'], data['ContactName'], data['ContactEmail'], now, existing['DomainId']))
    else:
        db.execute('''INSERT INTO DomainIdentity (DomainId, DomainName, OrgName, ContactName, ContactEmail)
                      VALUES (?, ?, ?, ?, ?)''',
                   (str(uuid.uuid4()), data['DomainName'], data['OrgName'], data['ContactName'], data['ContactEmail']))
    write_audit(db, 'IDENTITY_UPDATED', session['user_id'], 'User', 'DomainIdentity', 'self', 'Domain identity updated')
    db.commit()
    return jsonify({'message': 'Identity saved'})

# ============================================================
# USERS
# ============================================================

@app.route('/api/users', methods=['GET'])
@login_required
def list_users():
    db = get_db()
    rows = db.execute('SELECT UserId, DisplayName, Email, BadgeId, Agency, Role, Status, CreatedAt FROM Users ORDER BY CreatedAt DESC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    data = request.get_json()
    db = get_db()
    uid = str(uuid.uuid4())
    pwd_hash = hashlib.sha256(data.get('Password','changeme').encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    db.execute('''INSERT INTO Users (UserId, DisplayName, Email, PasswordHash, BadgeId, Agency, Role, CreatedAt, UpdatedAt)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
               (uid, data['DisplayName'], data['Email'], pwd_hash,
                data.get('BadgeId',''), data.get('Agency',''), data.get('Role','Investigator'), now, now))
    write_audit(db, 'USER_CREATED', session['user_id'], 'User', 'User', uid, f"User created: {data['Email']}")
    db.commit()
    return jsonify({'message': 'User created', 'UserId': uid}), 201

@app.route('/api/users/<user_id>/status', methods=['POST'])
@login_required
@admin_required
def update_user_status(user_id):
    data = request.get_json()
    new_status = data.get('Status')
    if new_status not in ('Active','Suspended','Blacklisted'):
        return jsonify({'error': 'Invalid status'}), 400
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    db.execute('UPDATE Users SET Status=?, UpdatedAt=? WHERE UserId=?', (new_status, now, user_id))
    if new_status in ('Suspended','Blacklisted'):
        db.execute('''INSERT INTO RevocationRecords (RevocationId, TargetType, TargetId, Reason, IssuedByUserId)
                      VALUES (?, 'User', ?, ?, ?)''',
                   (str(uuid.uuid4()), user_id, data.get('Reason','No reason given'), session['user_id']))
    write_audit(db, f'USER_{new_status.upper()}', session['user_id'], 'User', 'User', user_id, f'User status: {new_status}')
    db.commit()
    return jsonify({'message': f'User status updated to {new_status}'})

# ============================================================
# DEVICES
# ============================================================

@app.route('/api/devices', methods=['GET'])
@login_required
def list_devices():
    db = get_db()
    rows = db.execute('SELECT * FROM Devices ORDER BY RegisteredAt DESC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/devices', methods=['POST'])
@login_required
@admin_required
def create_device():
    data = request.get_json()
    db = get_db()
    did = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute('''INSERT INTO Devices (DeviceId, Hostname, HardwareFingerprint, TPMAvailable, RegisteredAt, UpdatedAt)
                  VALUES (?, ?, ?, ?, ?, ?)''',
               (did, data['Hostname'], data.get('HardwareFingerprint',''), data.get('TPMAvailable',0), now, now))
    write_audit(db, 'DEVICE_REGISTERED', session['user_id'], 'User', 'Device', did, f"Device registered: {data['Hostname']}")
    db.commit()
    return jsonify({'message': 'Device registered', 'DeviceId': did}), 201

# ============================================================
# NODES
# ============================================================

@app.route('/api/nodes', methods=['GET'])
@login_required
def list_nodes():
    db = get_db()
    rows = db.execute('''
        SELECT n.*, d.Hostname, u.DisplayName as PrimaryUserName
        FROM Nodes n
        LEFT JOIN Devices d ON n.DeviceId = d.DeviceId
        LEFT JOIN Users u ON n.PrimaryUserId = u.UserId
        ORDER BY n.CreatedAt DESC
    ''').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/nodes/<node_id>/status', methods=['POST'])
@login_required
@admin_required
def update_node_status(node_id):
    data = request.get_json()
    new_state = data.get('State')
    if new_state not in ('Active','Suspended','Revoked'):
        return jsonify({'error': 'Invalid state'}), 400
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    db.execute('UPDATE Nodes SET State=?, UpdatedAt=? WHERE NodeId=?', (new_state, now, node_id))
    if new_state in ('Suspended','Revoked'):
        db.execute('''INSERT INTO RevocationRecords (RevocationId, TargetType, TargetId, Reason, IssuedByUserId)
                      VALUES (?, 'Node', ?, ?, ?)''',
                   (str(uuid.uuid4()), node_id, data.get('Reason','No reason given'), session['user_id']))
    write_audit(db, f'NODE_{new_state.upper()}', session['user_id'], 'User', 'Node', node_id, f'Node state: {new_state}')
    db.commit()
    return jsonify({'message': f'Node state updated to {new_state}'})

# ============================================================
# NODE REGISTRATION PACKETS
# ============================================================

@app.route('/api/packets', methods=['GET'])
@login_required
def list_packets():
    db = get_db()
    rows = db.execute('SELECT * FROM NodeRegistrationPackets ORDER BY SubmittedAt DESC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/packets', methods=['POST'])
def submit_packet():
    data = request.get_json()
    db = get_db()
    packet_id = str(uuid.uuid4())
    node_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute('''INSERT INTO Nodes (NodeId, NodeName, State, CreatedAt, UpdatedAt)
                  VALUES (?, ?, 'Unregistered', ?, ?)''',
               (node_id, data.get('ProposedNodeName','Unknown'), now, now))
    db.execute('''INSERT INTO NodeRegistrationPackets
                  (PacketId, NodeId, DeviceFingerprint, Hostname, TPMInfo, PublicKeyMaterial, ProposedNodeName, ProposedUserId, PacketType, SubmittedAt)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
               (packet_id, node_id, data.get('DeviceFingerprint',''), data.get('Hostname',''),
                data.get('TPMInfo',''), data.get('PublicKeyMaterial',''),
                data.get('ProposedNodeName',''), data.get('ProposedUserId',''),
                data.get('PacketType','Registration'), now))
    write_audit(db, 'PACKET_SUBMITTED', 'system', 'System', 'NodeRegistrationPacket', packet_id, f"Packet submitted: {data.get('Hostname','')}")
    db.commit()
    return jsonify({'message': 'Packet submitted', 'PacketId': packet_id, 'NodeId': node_id}), 201

@app.route('/api/packets/<packet_id>/decision', methods=['POST'])
@login_required
@admin_required
def decide_packet(packet_id):
    data = request.get_json()
    decision = data.get('Decision')
    if decision not in ('Approved','Rejected'):
        return jsonify({'error': 'Invalid decision'}), 400
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    packet = db.execute('SELECT * FROM NodeRegistrationPackets WHERE PacketId=?', (packet_id,)).fetchone()
    if not packet:
        return jsonify({'error': 'Packet not found'}), 404
    db.execute('''UPDATE NodeRegistrationPackets
                  SET Status=?, ProcessedAt=?, ProcessedBy=?, DecisionReason=?
                  WHERE PacketId=?''',
               (decision, now, session['user_id'], data.get('Reason',''), packet_id))
    if decision == 'Approved':
        interval = data.get('ReRegistrationIntervalDays', 90)
        expiry = (datetime.now(timezone.utc) + timedelta(days=interval)).isoformat()
        db.execute('''UPDATE Nodes SET State='Active', RegistrationExpiryUtc=?, LastRegistrationAt=?, 
                      ReRegistrationIntervalDays=?, UpdatedAt=? WHERE NodeId=?''',
                   (expiry, now, interval, now, packet['NodeId']))
    write_audit(db, f'PACKET_{decision.upper()}', session['user_id'], 'User', 'NodeRegistrationPacket', packet_id, f'Packet {decision}')
    db.commit()
    return jsonify({'message': f'Packet {decision}'})

# ============================================================
# ENGAGEMENT CARDS
# ============================================================

@app.route('/api/cards', methods=['GET'])
@login_required
def list_cards():
    db = get_db()
    rows = db.execute('SELECT * FROM EngagementCards ORDER BY CreatedAt DESC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/cards', methods=['POST'])
@login_required
def create_card():
    data = request.get_json()
    db = get_db()
    card_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute('''INSERT INTO EngagementCards
                  (EngagementCardId, CardTitle, CreatingNodeId, CreatingUserId, IncidentType, Severity, CreatedAt, UpdatedAt)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
               (card_id, data['CardTitle'], data.get('CreatingNodeId'),
                session['user_id'], data.get('IncidentType',''), data.get('Severity','Medium'), now, now))
    write_audit(db, 'CARD_CREATED', session['user_id'], 'User', 'EngagementCard', card_id, f"Card created: {data['CardTitle']}")
    db.commit()
    return jsonify({'message': 'Engagement card created', 'EngagementCardId': card_id}), 201

@app.route('/api/cards/<card_id>/lifecycle', methods=['POST'])
@login_required
def update_card_lifecycle(card_id):
    data = request.get_json()
    new_state = data.get('LifecycleState')
    valid = ('Open','Active','Suspended','Closed','Archived','Cold')
    if new_state not in valid:
        return jsonify({'error': 'Invalid lifecycle state'}), 400
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    db.execute('UPDATE EngagementCards SET LifecycleState=?, UpdatedAt=? WHERE EngagementCardId=?',
               (new_state, now, card_id))
    write_audit(db, f'CARD_{new_state.upper()}', session['user_id'], 'User', 'EngagementCard', card_id, f'Card lifecycle: {new_state}')
    db.commit()
    return jsonify({'message': f'Card lifecycle updated to {new_state}'})

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
# EXPORT BUNDLE (for Master Registrar)
# ============================================================

@app.route('/api/export/bundle', methods=['POST'])
@login_required
@admin_required
def export_bundle():
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    identity = db.execute('SELECT * FROM DomainIdentity LIMIT 1').fetchone()
    nodes = db.execute('SELECT * FROM Nodes').fetchall()
    cards = db.execute('SELECT * FROM EngagementCards').fetchall()
    packets = db.execute('SELECT * FROM NodeRegistrationPackets WHERE Status="Approved"').fetchall()
    bundle = {
        'BundleType': 'DomainTelemetry',
        'GeneratedAt': now,
        'DomainIdentity': dict(identity) if identity else {},
        'Nodes': [dict(n) for n in nodes],
        'EngagementCards': [dict(c) for c in cards],
        'ApprovedPackets': [dict(p) for p in packets]
    }
    bundle_id = str(uuid.uuid4())
    bundle_json = json.dumps(bundle, indent=2)
    db.execute('''INSERT INTO OutboundBundles (BundleId, BundleType, PayloadJson, ExportedAt, ExportedBy)
                  VALUES (?, 'UsageTelemetry', ?, ?, ?)''',
               (bundle_id, bundle_json, now, session['user_id']))
    write_audit(db, 'BUNDLE_EXPORTED', session['user_id'], 'User', 'OutboundBundle', bundle_id, 'Telemetry bundle exported')
    db.commit()
    return jsonify({'BundleId': bundle_id, 'Bundle': bundle})

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
    print('[START] Domain Registrar running on http://localhost:5001')
    app.run(host='0.0.0.0', port=5001, debug=False)
