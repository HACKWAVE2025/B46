import sqlite3
import os
import io
import re
import json
import google.generativeai as genai
from flask import Flask, request, jsonify, session, send_from_directory, g, send_file
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

# --- App Configuration ---
app = Flask(_name_)
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SESSION_TYPE"] = "filesystem"
app.config["UPLOAD_FOLDER"] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
Session(app)

DATABASE = 'database.db'

# --- Database Helper Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Users Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('Patient', 'Doctor', 'Admin')),
                full_name TEXT
            );
        ''')
        # Doctor Credentials Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS doctor_credentials (
                doctor_id INTEGER PRIMARY KEY,
                specialty TEXT,
                document_name TEXT,
                document_data BLOB,
                verified INTEGER DEFAULT 0,
                FOREIGN KEY (doctor_id) REFERENCES users (id)
            );
        ''')
        # Appointments Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                doctor_id INTEGER NOT NULL,
                appointment_time TEXT NOT NULL,
                status TEXT DEFAULT 'Scheduled',
                FOREIGN KEY (patient_id) REFERENCES users (id),
                FOREIGN KEY (doctor_id) REFERENCES users (id)
            );
        ''')
        # Messages Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            );
        ''')
        # Consultations Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS consultations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appointment_id INTEGER NOT NULL,
                summary TEXT,
                translated_summary TEXT,
                audio_path TEXT,
                FOREIGN KEY (appointment_id) REFERENCES appointments (id)
            );
        ''')
        # Prescriptions Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS prescriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                appointment_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                pdf_data BLOB,
                issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (appointment_id) REFERENCES appointments (id)
            );
        ''')
        # Create a default admin if not exists
        cursor.execute("SELECT * FROM users WHERE email = 'admin@health.ai'")
        if cursor.fetchone() is None:
            cursor.execute("INSERT INTO users (email, password, role, full_name) VALUES (?, ?, ?, ?)",
                           ('admin@health.ai', generate_password_hash('admin123'), 'Admin', 'Admin User'))
        db.commit()


# --- API Key Management ---
@app.route('/api/set_api_key', methods=['POST'])
def set_api_key():
    data = request.get_json()
    if not data or 'api_key' not in data:
        return jsonify({"error": "API key is required"}), 400
    session['gemini_api_key'] = data['api_key']
    return jsonify({"message": "API key set successfully"}), 200

# --- User & Auth Routes ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    full_name = data.get('full_name')
    specialty = data.get('specialty') # for doctors

    if not all([email, password, role, full_name]):
        return jsonify({'error': 'Missing required fields'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    if cursor.fetchone():
        return jsonify({'error': 'Email already registered'}), 409

    hashed_password = generate_password_hash(password)
    cursor.execute('INSERT INTO users (email, password, role, full_name) VALUES (?, ?, ?, ?)',
                   (email, hashed_password, role, full_name))
    user_id = cursor.lastrowid
    
    if role == 'Doctor':
        cursor.execute('INSERT INTO doctor_credentials (doctor_id, specialty) VALUES (?, ?)', (user_id, specialty))

    db.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['role'] = user['role']
        return jsonify({'message': 'Login successful', 'role': user['role'], 'name': user['full_name']}), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/current_user')
def current_user():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id, email, role, full_name FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user_data = dict(user)
    if user['role'] == 'Doctor':
        cursor.execute('SELECT specialty, verified FROM doctor_credentials WHERE doctor_id = ?', (user['id'],))
        doc_data = cursor.fetchone()
        if doc_data:
            user_data.update(dict(doc_data))

    return jsonify(user_data), 200

# --- Doctor Specific Routes ---
@app.route('/api/upload_credential', methods=['POST'])
def upload_credential():
    if 'user_id' not in session or session['role'] != 'Doctor':
        return jsonify({'error': 'Unauthorized'}), 401

    if 'credential' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['credential']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        filename = secure_filename(file.filename)
        file_data = file.read()
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            UPDATE doctor_credentials SET document_name = ?, document_data = ? WHERE doctor_id = ?
        ''', (filename, file_data, session['user_id']))
        db.commit()

        return jsonify({'message': 'Credential uploaded successfully'}), 200

@app.route('/api/doctors')
def get_doctors():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT u.id, u.full_name, dc.specialty FROM users u
        JOIN doctor_credentials dc ON u.id = dc.doctor_id
        WHERE u.role = 'Doctor' AND dc.verified = 1
    ''')
    doctors = [dict(row) for row in cursor.fetchall()]
    return jsonify(doctors), 200
    
# --- Admin Routes ---
@app.route('/api/admin/unverified_doctors')
def get_unverified_doctors():
    if 'user_id' not in session or session['role'] != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT u.id, u.full_name, dc.specialty, dc.document_name FROM users u
        JOIN doctor_credentials dc ON u.id = dc.doctor_id
        WHERE dc.verified = 0 AND dc.document_name IS NOT NULL
    ''')
    doctors = [dict(row) for row in cursor.fetchall()]
    return jsonify(doctors), 200

@app.route('/api/admin/credential/<int:doctor_id>')
def get_credential_file(doctor_id):
    if 'user_id' not in session or session['role'] != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT document_name, document_data FROM doctor_credentials WHERE doctor_id = ?', (doctor_id,))
    doc = cursor.fetchone()
    if doc and doc['document_data']:
        return send_file(io.BytesIO(doc['document_data']), mimetype='application/octet-stream', as_attachment=True, download_name=doc['document_name'])
    return jsonify({'error': 'File not found'}), 404


@app.route('/api/admin/verify_doctor', methods=['POST'])
def verify_doctor():
    if 'user_id' not in session or session['role'] != 'Admin':
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    doctor_id = data.get('doctor_id')
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE doctor_credentials SET verified = 1 WHERE doctor_id = ?', (doctor_id,))
    db.commit()

    return jsonify({'message': 'Doctor verified successfully'}), 200

# --- Appointment Routes ---
@app.route('/api/doctor/availability/<int:doctor_id>')
def get_availability(doctor_id):
    # This is a mock implementation. A real app would have a complex calendar system.
    today = datetime.now()
    availability = []
    for i in range(7): # Next 7 days
        day = today + timedelta(days=i)
        for hour in range(9, 17): # 9am to 5pm
            if hour != 12: # Lunch break
                slot = day.replace(hour=hour, minute=0, second=0, microsecond=0)
                availability.append(slot.isoformat())
    return jsonify(availability), 200

@app.route('/api/book_appointment', methods=['POST'])
def book_appointment():
    if 'user_id' not in session or session['role'] != 'Patient':
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    doctor_id = data.get('doctor_id')
    appointment_time = data.get('appointment_time')
    patient_id = session['user_id']
    
    db = get_db()
    cursor = db.cursor()
    # In a real app, you would check for conflicts here
    cursor.execute('INSERT INTO appointments (patient_id, doctor_id, appointment_time) VALUES (?, ?, ?)',
                   (patient_id, doctor_id, appointment_time))
    db.commit()
    
    return jsonify({'message': 'Appointment booked successfully'}), 201

@app.route('/api/appointments')
def get_appointments():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    role = session['role']
    
    db = get_db()
    cursor = db.cursor()

    query = ''
    if role == 'Patient':
        query = '''
            SELECT a.id, a.appointment_time, a.status, u.full_name as doctor_name FROM appointments a
            JOIN users u ON a.doctor_id = u.id
            WHERE a.patient_id = ? ORDER BY a.appointment_time DESC
        '''
    elif role == 'Doctor':
        query = '''
            SELECT a.id, a.appointment_time, a.status, u.full_name as patient_name FROM appointments a
            JOIN users u ON a.patient_id = u.id
            WHERE a.doctor_id = ? ORDER BY a.appointment_time DESC
        '''
    
    cursor.execute(query, (user_id,))
    appointments = [dict(row) for row in cursor.fetchall()]
    return jsonify(appointments), 200


# --- AI Routes ---
@app.route('/api/symptom_checker', methods=['POST'])
def symptom_checker():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    if 'gemini_api_key' not in session:
        return jsonify({"error": "API key not set. Please provide your API key."}), 400

    try:
        genai.configure(api_key=session['gemini_api_key'])
        model = genai.GenerativeModel('gemini-2.0-flash')
    except Exception as e:
        return jsonify({"error": f"Failed to configure AI model: {e}"}), 500

    data = request.get_json()
    symptoms = data.get('symptoms')
    if not symptoms:
        return jsonify({'error': 'Symptoms are required'}), 400

    prompt = f"""
    As an AI medical assistant, analyze the following symptoms and provide a list of potential conditions and suggest the most appropriate type of medical specialist to consult.
    Symptoms: "{symptoms}"

    IMPORTANT: Respond with ONLY a valid JSON object in the following format. Do not include any other text, explanations, or markdown formatting like json.

    {{
      "potential_conditions": ["Common Cold", "Influenza", "Allergic Rhinitis"],
      "suggested_specialist": "General Physician or an Allergist"
    }}
    """

    try:
        response = model.generate_content(prompt)
        raw_text = response.text
        json_string = None

        # First, try to find a JSON markdown block
        match = re.search(r'json\s*([\s\S]?)\s```', raw_text)
        if match:
            json_string = match.group(1).strip()
        else:
            # If no markdown block, find the content between the first '{' and the last '}'
            start_index = raw_text.find('{')
            end_index = raw_text.rfind('}')
            if start_index != -1 and end_index != -1 and end_index > start_index:
                json_string = raw_text[start_index:end_index + 1]

        if not json_string:
            return jsonify({'error': 'AI returned a non-JSON response. Could not parse the result.'}), 500

        # Parse the extracted string to ensure it's valid JSON
        result_data = json.loads(json_string)
        
        return jsonify(result_data), 200
    except json.JSONDecodeError:
        return jsonify({'error': 'AI returned an invalid JSON format. Could not parse the result.'}), 500
    except Exception as e:
        return jsonify({'error': f'AI generation failed: {str(e)}'}), 500

@app.route('/api/ai_scribe', methods=['POST'])
def ai_scribe():
    if 'user_id' not in session or session['role'] != 'Doctor':
        return jsonify({'error': 'Unauthorized'}), 401
    if 'gemini_api_key' not in session:
        return jsonify({"error": "API key not set"}), 400

    if 'audio' not in request.files:
        return jsonify({'error': 'No audio file part'}), 400
    
    notes = request.form.get('notes', '')
    appointment_id = request.form.get('appointment_id')

    # For this prototype, we'll use the provided text notes as the "transcription".
    if not notes:
        return jsonify({'error': "Please provide textual notes of the consultation."}), 400

    try:
        genai.configure(api_key=session['gemini_api_key'])
        model = genai.GenerativeModel('gemini-2.0-flash')
    except Exception as e:
        return jsonify({"error": f"Failed to configure AI model: {e}"}), 500

    prompt_summary = f"""
    Based on the following doctor's notes from a patient consultation, create a structured text summary with sections for "Symptoms", "Diagnosis", and "Advice".
    Notes: "{notes}"
    """
    summary_response = model.generate_content(prompt_summary)
    summary_text = summary_response.text

    prompt_translation = f"""
    Translate the following medical summary into Hindi.
    Summary: "{summary_text}" 
    """
    
    try:
        translation_response = model.generate_content(prompt_translation)
        translated_text = translation_response.text

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'INSERT INTO consultations (appointment_id, summary, translated_summary) VALUES (?, ?, ?)',
            (appointment_id, summary_text, translated_text)
        )
        db.commit()

        return jsonify({'summary': summary_text, 'translation': translated_text}), 200
    except Exception as e:
        return jsonify({'error': f'AI processing failed: {e}'}), 500
        
# --- Messaging Routes ---
@app.route('/api/messages/<int:other_user_id>')
def get_messages(other_user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = session['user_id']
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        SELECT * FROM messages 
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    ''', (user_id, other_user_id, other_user_id, user_id))
    
    messages = [dict(row) for row in cursor.fetchall()]
    return jsonify(messages), 200

@app.route('/api/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    sender_id = session['user_id']
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
                   (sender_id, receiver_id, content))
    db.commit()
    
    return jsonify({'message': 'Message sent'}), 201

# --- Health History & Prescription Routes ---
@app.route('/api/health_history')
def get_health_history():
    if 'user_id' not in session or session['role'] != 'Patient':
        return jsonify({'error': 'Unauthorized'}), 401

    patient_id = session['user_id']
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        SELECT 
            a.id as appointment_id,
            a.appointment_time,
            u.full_name as doctor_name,
            c.summary,
            c.translated_summary,
            p.id as prescription_id,
            p.content as prescription_content
        FROM appointments a
        JOIN users u ON a.doctor_id = u.id
        LEFT JOIN consultations c ON a.id = c.appointment_id
        LEFT JOIN prescriptions p ON a.id = p.appointment_id
        WHERE a.patient_id = ?
        ORDER BY a.appointment_time DESC
    ''', (patient_id,))
    
    history = [dict(row) for row in cursor.fetchall()]
    return jsonify(history), 200

@app.route('/api/generate_prescription', methods=['POST'])
def generate_prescription():
    if 'user_id' not in session or session['role'] != 'Doctor':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    appointment_id = data.get('appointment_id')
    content = data.get('content')
    
    # The PDF generation is handled client-side in this version.
    db = get_db()
    cursor = db.cursor()
    cursor.execute('INSERT INTO prescriptions (appointment_id, content) VALUES (?, ?)',
                   (appointment_id, content))
    db.commit()
    
    return jsonify({'message': 'Prescription created successfully'}), 201

# --- Serving Frontend ---
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


# --- Main Execution ---
if _name_ == '_main_':
    init_db()
    app.run(host='0.0.0.0', port=5000)