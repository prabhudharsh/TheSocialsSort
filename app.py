import os
import re
import time
import random
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, jsonify, redirect, url_for
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


# Global voting control
VOTING_START = datetime.now() + timedelta(minutes=1)
FORCE_START = False

# Voting categories - easily changeable
CATEGORIES = [
    "Smartest in class",
    "Can be found napping in class",
    "Handsome/Beautiful",
    "Annoying"
]

# -----------------------
# Config & constants
# -----------------------
OTP_TTL_SECONDS = 5 * 60  # 5 minutes
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
EMAIL_REGEX = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
MIN_PASSWORD_LENGTH = 6
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

# -----------------------
# Database connection
# -----------------------
def get_db_connection():
    conn = sqlite3.connect(os.getenv('DB_PATH'))
    conn.row_factory = sqlite3.Row
    return conn

# -----------------------
# Input validation
# -----------------------
def validate_signup(username, email, password):
    if not USERNAME_REGEX.match(username):
        return "Username must be 3-20 characters and alphanumeric."
    if not EMAIL_REGEX.match(email):
        return "Invalid email format."
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    return None

# -----------------------
# Email sending
# -----------------------
def send_otp_via_email(user_email, otp_code):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASSWORD')

    msg = EmailMessage()
    msg["Subject"] = "Your OTP Code"
    msg["From"] = sender_email
    msg["To"] = user_email
    msg.set_content(f"Your OTP code is: {otp_code}\nIt will expire in 5 minutes.")

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        print(f"OTP sent successfully to {user_email}")
    except Exception as e:
        print("Error sending email:", e)
        raise e


# -----------------------
# Landing page
# -----------------------
@app.route('/')
def landing():
    return render_template('index.html')

# -----------------------
# LOGIN AJAX with brute-force protection
# -----------------------
@app.route('/login_ajax', methods=['POST'])
def login_ajax():
    data = request.get_json()
    username = data.get('username')
    password_input = data.get('password')

    # Initialize failed attempts tracking
    if 'login_attempts' not in session:
        session['login_attempts'] = {}

    attempts = session['login_attempts'].get(username, {'count': 0, 'lock_until': None})

    # Check lockout
    now = datetime.now()
    lock_until = attempts.get('lock_until')
    if lock_until and now < lock_until:
        remaining = int((lock_until - now).total_seconds() // 60) + 1
        return jsonify({'status': 'danger', 'message': f'Too many failed attempts. Try again in {remaining} minutes.'})

    # Check credentials
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password, is_verified FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and check_password_hash(user['password'], password_input):
        # Successful login -> reset attempts
        session['login_attempts'][username] = {'count': 0, 'lock_until': None}
        session['user_id'] = user['id']
        session['username'] = username
        if not user['is_verified']:
            return jsonify({'status': 'warning', 'message': 'Please verify your email first.'})
        return jsonify({'status': 'success', 'message': 'Logged in successfully.'})
    else:
        # Failed login
        attempts['count'] += 1
        if attempts['count'] >= MAX_FAILED_ATTEMPTS:
            attempts['lock_until'] = now + timedelta(minutes=LOCKOUT_MINUTES)
            attempts['count'] = 0  # reset count after lock
        session['login_attempts'][username] = attempts
        return jsonify({'status': 'danger', 'message': 'Invalid username or password.'})

# -----------------------
# SIGNUP AJAX: check username/email & open OTP modal
# -----------------------
@app.route('/signup_ajax', methods=['POST'])
def signup_ajax():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Input validation
    error = validate_signup(username, email, password)
    if error:
        return jsonify({'status': 'warning', 'message': error})

    conn = get_db_connection()
    cur = conn.cursor()
    # Check username/email uniqueness
    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'status': 'warning', 'message': 'Username is already taken.'})

    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({'status': 'warning', 'message': 'Email is already in use.'})

    cur.close()
    conn.close()

    # Store pending user with OTP + timestamp
    otp = str(random.randint(100000, 999999))
    session['pending_user'] = {
        'username': username,
        'email': email,
        'password_plain': password,
        'otp': otp,
        'otp_created_at': int(time.time())
    }

    return jsonify({'status': 'otp_modal', 'message': 'Proceed to OTP verification.'})

# -----------------------
# SEND OTP AJAX
# -----------------------
@app.route('/send_otp_ajax', methods=['POST'])
def send_otp_ajax():
    pending = session.get('pending_user')
    if not pending:
        return jsonify({'status': 'error', 'message': 'Session expired. Please try again.'})

    # Refresh OTP if expired
    now = int(time.time())
    created = pending.get('otp_created_at', 0)
    if now - created > OTP_TTL_SECONDS:
        pending['otp'] = str(random.randint(100000, 999999))
        pending['otp_created_at'] = now
        session['pending_user'] = pending

    try:
        send_otp_via_email(pending['email'], pending['otp'])
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to send OTP: {e}'})

    return jsonify({'status': 'success', 'message': 'OTP sent to your email.'})

# -----------------------
# OTP verification AJAX
# -----------------------
@app.route('/verify_otp_ajax', methods=['POST'])
def verify_otp_ajax():
    data = request.get_json()
    entered_otp = data.get('otp')

    pending = session.get('pending_user')
    if not pending:
        return jsonify({'status': 'error', 'message': 'Session expired. Please try again.'})

    # Check OTP expiry
    now = int(time.time())
    created = pending.get('otp_created_at', 0)
    if now - created > OTP_TTL_SECONDS:
        session.pop('pending_user')
        return jsonify({'status': 'danger', 'message': 'OTP expired. Please sign up again.'})

    if entered_otp != pending['otp']:
        return jsonify({'status': 'danger', 'message': 'Invalid OTP. Please try again.'})

    # Persist user with hashed password
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        password_hash = generate_password_hash(pending['password_plain'])
        cur.execute(
            "INSERT INTO users (username, email, password, is_verified) VALUES (?, ?, ?, ?)",
            (pending['username'], pending['email'], password_hash, 1)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Username or email already exists.'})
    except sqlite3.Error as err:
        return jsonify({'status': 'error', 'message': f'Database error: {err}'})
    finally:
        cur.close()
        conn.close()

    session.pop('pending_user')
    return jsonify({'status': 'success', 'message': 'Signup successful! Redirecting to dashboard...'})


# -----------------------
# Admin Login Page
# -----------------------
from flask import redirect, url_for

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        admin_username = os.getenv('ADMIN_USERNAME')
        admin_password = os.getenv('ADMIN_PASSWORD')

        if username == admin_username and password == admin_password:
            session['admin'] = True
            return jsonify({'status': 'success', 'redirect': '/admin_dashboard'})
        else:
            return jsonify({'status': 'danger', 'message': 'Invalid admin credentials.'})

    # GET request: return HTML form
    return render_template('admin_login.html')

# -----------------------
# Admin Dashboard
# -----------------------
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    global VOTING_START, FORCE_START

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch all users
    cur.execute("SELECT username, full_name, email, gender FROM users")
    users = cur.fetchall()
    cur.close()
    conn.close()

    # Handle POST for updating voting time / force skip
    if request.method == 'POST':
        data = request.get_json()
        if 'new_time' in data:
            # Update countdown to a new datetime
            VOTING_START = datetime.strptime(data['new_time'], '%Y-%m-%d %H:%M:%S')
            FORCE_START = False
            return jsonify({'status': 'success', 'message': 'Voting time updated.'})
        elif data.get('force_start'):
            FORCE_START = True
            return jsonify({'status': 'success', 'message': 'Voting started immediately.'})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid action.'})

    return render_template('admin_dashboard.html', users=users, voting_start=VOTING_START)


# -----------------------
# Dashboard
# -----------------------
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return "Not logged in.", 403

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT full_name, bio, gender FROM users WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user['full_name'] or not user['bio']:
        return redirect(url_for('complete_profile'))
    if not user['gender']:
        return redirect(url_for('select_gender'))

    # Calculate time left for universal countdown
    now = datetime.now()
    time_left = int((VOTING_START - now).total_seconds())
    if time_left < 0:
        time_left = 0

    # Render dashboard template with universal countdown
    return render_template('dashboard.html', username=session['username'], time_left=time_left)

# -----------------------
# Complete Profile
# -----------------------
@app.route('/complete_profile', methods=['GET', 'POST'])
def complete_profile():
    if 'user_id' not in session:
        return "Not logged in.", 403

    if request.method == 'POST':
        data = request.get_json()
        full_name = data.get('full_name', '').strip()
        bio = data.get('bio', '').strip()

        if not full_name or not bio:
            return jsonify({'status': 'error', 'message': 'Full name and bio cannot be empty.'})

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET full_name = ?, bio = ? WHERE id = ?",
            (full_name, bio, session['user_id'])
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'status': 'success', 'redirect': '/select_gender'})

    # GET request: return HTML template
    return render_template('complete_profile.html')

# -----------------------
# Complete Profile
# -----------------------
@app.route('/select_gender', methods=['GET', 'POST'])
def select_gender():
    if 'user_id' not in session:
        return "Not logged in.", 403

    if request.method == 'POST':
        data = request.get_json()
        gender = data.get('gender', '').lower()
        if gender not in ['male', 'female']:
            return jsonify({'status': 'error', 'message': 'Select a valid gender.'})

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET gender = ? WHERE id = ?",
            (gender, session['user_id'])
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'status': 'success', 'redirect': '/dashboard'})

    # GET request: return HTML template
    return render_template('select_gender.html')

# -----------------------
# Profile
# -----------------------
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('landing'))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT username, full_name, email, gender FROM users WHERE id = ?", 
        (session['user_id'],)
    )
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return "User not found.", 404

    return render_template('profile.html', user=user)

# -----------------------
# category
# -----------------------

@app.route('/category')
def category():
    if 'username' not in session:
        return redirect(url_for('landing'))

    return render_template('category.html', categories=CATEGORIES)

# -----------------------
# Category detail page route
# -----------------------
@app.route('/category/<int:cat_id>')
def category_page(cat_id):
    if 'username' not in session:
        return redirect(url_for('landing'))

    # Ensure valid category index
    if 1 <= cat_id <= len(VOTING_CATEGORIES):
        category_name = VOTING_CATEGORIES[cat_id - 1]
        return f"<h1>{category_name}</h1><p>Voting options will go here.</p>"
    else:
        return "Invalid category.", 404

# -----------------------
# Voting Page
# -----------------------
@app.route('/voting_page')
def voting_page():
    if 'username' not in session:
        return redirect(url_for('landing'))
    return "<h1>Welcome to the Voting Page!</h1><p>Voting will happen here.</p>"



# -----------------------
# Run app
# -----------------------
if __name__ == '__main__':
    app.run(debug=True)
