from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

import os
import sqlite3
import numpy as np
import pickle
import tensorflow as tf

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# === Flask-Login Setup ===
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

DATABASE = 'your_database.db'

# === User Class ===
class User(UserMixin):
    def __init__(self, id_, username, is_admin=False):
        self.id = id_
        self.username = username



@login_manager.user_loader
def load_user(user_id):
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()
    cur.execute("SELECT id, username, is_admin FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    con.close()
    if user:
        return User(user[0], user[1], bool(user[2]))
    return None


# === Database ===
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    con = sqlite3.connect(DATABASE)
    cur = con.cursor()

    # Users Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)

    # Logs Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Medicine Reminders Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS medicine_reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            medicine_name TEXT,
            dosage TEXT,
            schedule TEXT,
            start_date TEXT,
            end_date TEXT,
            is_completed INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Diagnosis Logs Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS diagnosis_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            symptoms TEXT,
            prediction TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # ✅ Diagnoses Table (fix for the error)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS diagnoses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            symptoms TEXT,
            prediction TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    con.commit()
    con.close()
    print("✅ All tables initialized successfully.")


# Initialize DB at startup
if not os.path.exists(DATABASE):
    init_db()
else:
    # Optional: Ensure all tables exist even if DB file is already present
    init_db()


# === Load Model and Preprocessors ===
model = tf.keras.models.load_model("models/diagnosis_model.h5")
with open("models/scaler.pkl", "rb") as f:
    scaler = pickle.load(f)
with open("models/label_encoder.pkl", "rb") as f:
    label_encoder = pickle.load(f)
with open("models/X_columns.pkl", "rb") as f:
    all_symptoms = pickle.load(f)


# === Routes ===
ADMIN_SECRET = "06182127"  # 🔒 Keep this safe!

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        secret_key = request.form['secret_key']

        if secret_key != ADMIN_SECRET:
            flash("Invalid admin secret key.", "danger")
            return render_template('admin_register.html')

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('admin_register.html')

        cur = get_db().cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        if cur.fetchone():
            flash("Username already exists.", "danger")
            return render_template('admin_register.html')

        hashed_password = generate_password_hash(password)
        cur.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", (username, hashed_password))
        get_db().commit()

        flash("Admin account created successfully!", "success")
        return redirect(url_for('login'))

    return render_template('admin_register.html')


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')

        cur = get_db().cursor()
        cur.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
        existing_user = cur.fetchone()

        if existing_user:
            flash("Username or Email already registered.", "danger")
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password))
        get_db().commit()

        user_id = cur.lastrowid
        login_user(User(user_id, username))  # Make sure User class is properly defined
        flash("Account created successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form

        cur = get_db().cursor()
        cur.execute("SELECT id, username, password, is_admin FROM users WHERE username=? OR email=?", (email, email))
        user = cur.fetchone()

        if user and check_password_hash(user[2], password):
            login_user(User(user[0], user[1], bool(user[3])), remember=remember)
            flash(f"Welcome back, {user[1]}!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid credentials", "danger")

    return render_template('login.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for('login'))
@app.route('/guest_login' , methods=['GET', 'POST']) 
def guest_login():
    # Set guest session data
    session['user_type'] = 'guest'
    session['username'] = 'Guest'
    flash("Logged in as Guest. Data won't be saved.", "info")

    return redirect(url_for('guest_dashboard'))


# Guest Login Route
@app.route('/guest_dashboard', methods=['GET'])
def guest_dashboard():
    # Check if the user is authenticated or a guest
    username = session.get('username', 'Guest')
    
    return render_template('guest_dashboard.html', username=username)
@app.route('/guest_logout')
def guest_logout():
    # Clear guest session data
    session.pop('user_type', None)
    session.pop('username', None)
    flash("Logged out from Guest account.", "info")
    return redirect(url_for('login'))

# Upgrade Guest Route
@app.route('/upgrade_guest', methods=['GET', 'POST'])
def upgrade_guest():
    if session.get('user_type') != 'guest':
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('upgrade_guest.html')

        cur = get_db().cursor()
        cur.execute("SELECT * FROM users WHERE username=? OR email=?", (username, email))
        if cur.fetchone():
            flash("Username or Email already exists.", "danger")
            return render_template('upgrade_guest.html')

        hashed_password = generate_password_hash(password)
        cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_password))
        get_db().commit()
        user_id = cur.lastrowid

        login_user(User(user_id, username))  # Assuming User class exists
        session.pop('user_type', None)
        session.pop('username', None)
        flash("Upgraded to full account successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('upgrade_guest.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = get_db().cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()

        if user and check_password_hash(user['password'], password):
            is_admin = user['is_admin'] == 1
            if is_admin:
                login_user(User(user['id'], username, is_admin=True))
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin'))
            else:
                flash('Access denied: Not an admin account.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('admin_login.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for('dashboard'))

    db = get_db()
    cur = db.cursor()

    # Fetch stats
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    admin_users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM logs WHERE username='Guest'")
    guest_logins = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM diagnoses")
    total_diagnoses = cur.fetchone()[0]

    # Fetch recent logs (latest 20)
    cur.execute("SELECT username, action, timestamp FROM logs ORDER BY timestamp DESC LIMIT 20")
    logs = cur.fetchall()

    stats = {
        "total_users": total_users,
        "admin_users": admin_users,
        "guest_logins": guest_logins,
        "total_diagnoses": total_diagnoses
    }

    return render_template("admin_dashboard.html", stats=stats, logs=logs)

@app.route('/dashboard')
@login_required
def dashboard():
    # Check if the user is authenticated or a guest
    username = current_user.username if current_user.is_authenticated else session.get('username', 'Guest')
    
    return render_template('dashboard.html', username=username)

@app.route('/diagnose', methods=['GET', 'POST'])
def diagnose():
    prediction = None

    if request.method == 'POST':
        symptoms_input = request.form['symptoms']
        symptom_list = [s.strip().lower() for s in symptoms_input.split(',') if s.strip()]

        input_data = np.zeros(len(all_symptoms))
        for symptom in symptom_list:
            if symptom in all_symptoms:
                input_data[all_symptoms.index(symptom)] = 1

        input_scaled = scaler.transform([input_data])
        prediction_index = np.argmax(model.predict(input_scaled), axis=1)[0]
        prediction = label_encoder.inverse_transform([prediction_index])[0]

        user_type = session.get('user_type', 'user')
        username = session.get('username', current_user.username if current_user.is_authenticated else "Guest")

        if user_type == 'guest':
            flash(f"[Guest] Consult a doctor for: {prediction}", "info")
        else:
            cur = get_db().cursor()
            cur.execute("INSERT INTO diagnosis_logs (username, symptoms, prediction) VALUES (?, ?, ?)",
                        (username, symptoms_input, prediction))
            get_db().commit()
            flash(f"Diagnosis complete: {prediction}", "info")

    return render_template("diagnosis.html", prediction=prediction)


@app.route('/reminders', methods=['GET', 'POST'])
@login_required
def reminders():
    cur = get_db().cursor()

    if request.method == 'POST':
        medicine = request.form['medicine']
        time = request.form['time']
        cur.execute("""
            INSERT INTO medicine_reminders (user_id, medicine_name, dosage, schedule, start_date, end_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (current_user.id, medicine, '', time, '', ''))
        get_db().commit()
        flash("Reminder added!", "success")
        return redirect(url_for('reminders'))

    cur.execute("SELECT * FROM medicine_reminders WHERE user_id=?", (current_user.id,))
    reminders = cur.fetchall()
    return render_template('reminders.html', reminders=reminders)


@app.route('/reminders/delete/<int:id>', methods=['POST'])
@login_required
def delete_reminder(id):
    cur = get_db().cursor()
    cur.execute("DELETE FROM medicine_reminders WHERE id=? AND user_id=?", (id, current_user.id))
    get_db().commit()
    flash("Reminder deleted.", "info")
    return redirect(url_for('reminders'))


@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    cur = get_db().cursor()

    stats = {
        "total_users": cur.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "admin_users": cur.execute("SELECT COUNT(*) FROM users WHERE is_admin=1").fetchone()[0],
        "total_diagnoses": cur.execute("SELECT COUNT(*) FROM diagnosis_logs").fetchone()[0]
    }

    cur.execute("SELECT username, symptoms, prediction, timestamp FROM diagnosis_logs ORDER BY timestamp DESC LIMIT 10")
    logs = cur.fetchall()

    return render_template("admin.html", stats=stats, logs=logs)
print(app.url_map)



if __name__ == '__main__':
    app.run(debug=True)
