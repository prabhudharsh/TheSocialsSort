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
from itertools import combinations

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')


# Global voting control
VOTING_START = datetime.now() + timedelta(seconds=0)
FORCE_START = False


# -----------------------
# Config & constants
# -----------------------
OTP_TTL_SECONDS = 5 * 60  # 5 minutes
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_]{3,20}$')
EMAIL_REGEX = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
MIN_PASSWORD_LENGTH = 6
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
MAX_VOTES = 10 # Global constant for max votes

# -----------------------
# Database connection
# -----------------------
def get_db_connection():
    conn = sqlite3.connect(os.getenv('DB_PATH'))
    conn.row_factory = sqlite3.Row
    return conn

# Voting categories
def get_categories():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM categories")
    categories = cur.fetchall()
    cur.close()
    conn.close()
    return categories

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
    msg["Subject"] = "Your Verification Code for The Social Sort"
    msg["From"] = sender_email
    msg["To"] = user_email
    message_body = f"""
Welcome to TheSocialSort!
Thank you for joining our constellation. To complete your sign-up, please use the following verification code:

Your OTP code is: {otp_code}
This code will expire in 5 minutes.

We're excited to have you!
--
TheSocialSortTeam

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠳⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⡴⢧⣀⠀⠀⣀⣠⠤⠤⠤⠤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⠏⢀⡴⠊⠁⠀⠀⠀⠀⠀⠀⠈⠙⠦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢶⣶⣒⣶⠦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣟⠲⡌⠙⢦⠈⢧⠀
⠀⠀⠀⣠⢴⡾⢟⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡴⢃⡠⠋⣠⠋⠀
⠐⠀⠞⣱⠋⢰⠁⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠤⢖⣋⡥⢖⣫⠔⠋⠀⠀⠀
⠈⠠⡀⠹⢤⣈⣙⠚⠶⠤⠤⠤⠴⠶⣒⣒⣚⣩⠭⢵⣒⣻⠭⢖⠏⠁⢀⣀⠀⠀⠀⠀
⠠⠀⠈⠓⠒⠦⠭⠭⠭⣭⠭⠭⠭⠭⠿⠓⠒⠛⠉⠉⠀⠀⣠⠏⠀⠀⠘⠞⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⢤⣀⠀⠀⠀⠀⠀⠀⣀⡤⠞⠁⠀⣰⣆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠘⠿⠀⠀⠀⠀⠀⠈⠉⠙⠒⠒⠛⠉⠁⠀⠀⠀⠉⢳⡞⠉⠀⠀⠀⠀⠀

"""

    msg.set_content(message_body)

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

    if 'login_attempts' not in session:
        session['login_attempts'] = {}

    attempts = session['login_attempts'].get(username, {'count': 0, 'lock_until': None})

    now = datetime.now()
    lock_until = attempts.get('lock_until')
    if lock_until and now < lock_until:
        remaining = int((lock_until - now).total_seconds() // 60) + 1
        return jsonify({'status': 'danger', 'message': f'Too many failed attempts. Try again in {remaining} minutes.'})

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, password, is_verified FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user and check_password_hash(user['password'], password_input):
        session['login_attempts'][username] = {'count': 0, 'lock_until': None}
        session['user_id'] = user['id']
        session['username'] = username
        if not user['is_verified']:
            return jsonify({'status': 'warning', 'message': 'Please verify your email first.'})
        return jsonify({'status': 'success', 'message': 'Logged in successfully.'})
    else:
        attempts['count'] += 1
        if attempts['count'] >= MAX_FAILED_ATTEMPTS:
            attempts['lock_until'] = now + timedelta(minutes=LOCKOUT_MINUTES)
            attempts['count'] = 0
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

    error = validate_signup(username, email, password)
    if error:
        return jsonify({'status': 'warning', 'message': error})

    conn = get_db_connection()
    cur = conn.cursor()
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

    now = int(time.time())
    created = pending.get('otp_created_at', 0)
    if now - created > OTP_TTL_SECONDS:
        session.pop('pending_user')
        return jsonify({'status': 'danger', 'message': 'OTP expired. Please sign up again.'})

    if entered_otp != pending['otp']:
        return jsonify({'status': 'danger', 'message': 'Invalid OTP. Please try again.'})

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        password_hash = generate_password_hash(pending['password_plain'])
        cur.execute(
            "INSERT INTO users (username, email, password, is_verified) VALUES (?, ?, ?, ?)",
            (pending['username'], pending['email'], password_hash, 1)
        )
        user_id = cur.lastrowid

        cur.execute("SELECT id FROM categories")
        categories = cur.fetchall()
        for category in categories:
            cur.execute(
                "INSERT INTO elo_ratings (user_id, category_id, rating) VALUES (?, ?, ?)",
                (user_id, category['id'], 1200)
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
    return jsonify({'status': 'success', 'message': 'Signup successful! Redirecting to login page...'})

# -----------------------
# Terms of Service Page
# -----------------------
@app.route('/tos')
def tos_page():
    user_gender = 'male' 
    if 'user_id' in session:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT gender FROM users WHERE id = ?", (session['user_id'],))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user:
            user_gender = user['gender']
            
    return render_template('tos.html', gender=user_gender)

# -----------------------
# Admin Routes
# -----------------------
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin'):
        return redirect(url_for('admin_dashboard'))

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

    return render_template('admin_login.html')

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    global VOTING_START, FORCE_START
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        data = request.get_json() or {}
        if 'new_time' in data:
            VOTING_START = datetime.strptime(data['new_time'], '%Y-%m-%d %H:%M:%S')
            FORCE_START = False
            return jsonify({'status': 'success', 'message': 'Voting time updated.'})
        elif data.get('force_start'):
            FORCE_START = True
            return jsonify({'status': 'success', 'message': 'Voting started immediately.'})
        else:
            return jsonify({'status': 'error', 'message': 'Invalid action.'})

    cur.execute("SELECT id, username, full_name, email, gender FROM users")
    users = cur.fetchall()
    cur.execute("SELECT id, name FROM categories")
    categories = cur.fetchall()

    leaderboards = {}
    for cat in categories:
        cat_id = cat['id']
        cur.execute("""
            SELECT u.id, u.username, u.full_name,
                   COALESCE(er.rating, 1200) AS rating,
                   (SELECT COUNT(*) 
                    FROM votes v 
                    WHERE (v.winner_id = u.id OR v.loser_id = u.id) 
                      AND v.category_id = ?) AS votes
            FROM users u
            LEFT JOIN elo_ratings er ON er.user_id = u.id AND er.category_id = ?
            ORDER BY rating DESC
        """, (cat_id, cat_id))
        leaderboard = cur.fetchall()

        rank = 1
        prev_rating = None
        for i, row in enumerate(leaderboard):
            rating = row['rating']
            if prev_rating is not None and rating < prev_rating:
                rank = i + 1
            row_dict = dict(row)
            row_dict['rank'] = rank
            leaderboard[i] = row_dict
            prev_rating = rating
        leaderboards[cat['name']] = leaderboard

    cur.close()
    conn.close()
    return render_template('admin_dashboard.html', users=users, categories=categories,
                           leaderboards=leaderboards, voting_start=VOTING_START)

# NEW ROUTE for managing users
@app.route('/admin/users', methods=['POST'])
def admin_manage_users():
    if not session.get('admin'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    data = request.get_json()
    action = data.get('action')
    user_id = data.get('user_id')

    if not action or not user_id:
        return jsonify({'status': 'error', 'message': 'Missing action or user ID.'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if action == 'update':
            full_name = data.get('full_name')
            email = data.get('email')
            gender = data.get('gender')
            cur.execute("UPDATE users SET full_name=?, email=?, gender=? WHERE id=?",
                        (full_name, email, gender, user_id))
            conn.commit()
            return jsonify({'status': 'success', 'message': 'User updated successfully.'})

        elif action == 'delete':
            # Comprehensive delete: remove user and all associated data
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
            cur.execute("DELETE FROM elo_ratings WHERE user_id = ?", (user_id,))
            cur.execute("DELETE FROM votes WHERE voter_id = ? OR winner_id = ? OR loser_id = ?", (user_id, user_id, user_id))
            conn.commit()
            return jsonify({'status': 'success', 'message': 'User and all associated data deleted.'})

        else:
            return jsonify({'status': 'error', 'message': 'Invalid action.'}), 400

    except sqlite3.Error as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': f'Database error: {e}'}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/admin_categories', methods=['GET', 'POST'])
def admin_categories():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        action = data.get('action')
        try:
            if action == 'add':
                new_name = data.get('name', '').strip()
                if not new_name:
                    return jsonify({'status': 'error', 'message': 'Category name cannot be empty.'}), 400
                cur.execute("INSERT INTO categories (name) VALUES (?)", (new_name,))
                cat_id = cur.lastrowid
                cur.execute("SELECT id FROM users")
                users = cur.fetchall()
                for user in users:
                    cur.execute(
                        "INSERT INTO elo_ratings (user_id, category_id, rating) VALUES (?, ?, ?)",
                        (user['id'], cat_id, 1200)
                    )
                conn.commit()
                return jsonify({'status': 'success', 'message': f'Category "{new_name}" added.'})
            elif action == 'rename':
                cat_id = data.get('id')
                new_name = data.get('name', '').strip()
                if not cat_id or not new_name:
                    return jsonify({'status': 'error', 'message': 'Invalid category ID or name.'}), 400
                cur.execute("UPDATE categories SET name=? WHERE id=?", (new_name, cat_id))
                conn.commit()
                return jsonify({'status': 'success', 'message': 'Category renamed.'})
            elif action == 'delete':
                cat_id = data.get('id')
                if not cat_id:
                    return jsonify({'status': 'error', 'message': 'Invalid category ID.'}), 400
                cur.execute("DELETE FROM categories WHERE id=?", (cat_id,))
                cur.execute("DELETE FROM elo_ratings WHERE category_id=?", (cat_id,))
                cur.execute("DELETE FROM votes WHERE category_id=?", (cat_id,))
                conn.commit()
                return jsonify({'status': 'success', 'message': 'Category deleted.'})
            else:
                return jsonify({'status': 'error', 'message': 'Invalid action.'}), 400
        except sqlite3.Error as e:
            return jsonify({'status': 'error', 'message': f'Database error: {e}'}), 500

    cur.execute("SELECT id, name FROM categories")
    categories = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_categories.html', categories=categories)

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))

# -----------------------
# Main App Routes
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

    now = datetime.now()
    time_left = int((VOTING_START - now).total_seconds())
    if time_left < 0:
        time_left = 0

    return render_template('dashboard.html', username=session['username'], time_left=time_left, gender=user['gender'])

# Add this new route to your app.py file

@app.route('/user_list')
def user_list():
    if 'user_id' not in session:
        return redirect(url_for('landing'))

    conn = get_db_connection()
    cur = conn.cursor()
    
    # Fetch the current user's gender for the profile icon in the navbar
    cur.execute("SELECT gender FROM users WHERE id = ?", (session['user_id'],))
    current_user = cur.fetchone()
    user_gender = current_user['gender'] if current_user else 'male'
    
    # Fetch all users to display on the page
    cur.execute("SELECT id, username, full_name, bio, gender FROM users")
    users = cur.fetchall()
    
    cur.close()
    conn.close()
    
    # Render the template, passing both the list of all users and the current user's gender
    return render_template('user_list.html', users=users, gender=user_gender)

# Add this new route to your app.py file

@app.route('/user/<username>')
def user_profile(username):
    if 'user_id' not in session:
        return redirect(url_for('landing'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch the data for the user whose profile is being viewed
    cur.execute("SELECT id, username, full_name, bio, gender FROM users WHERE username=?", (username,))
    user = cur.fetchone()

    # If the user doesn't exist, return a 404 error
    if not user:
        return "User not found", 404

    # Fetch the gender of the person viewing the profile for the navbar icon
    cur.execute("SELECT gender FROM users WHERE id=?", (session['user_id'],))
    viewer = cur.fetchone()
    viewer_gender = viewer['gender'] if viewer else 'male'

    # Fetch all categories to calculate ranks
    cur.execute("SELECT id, name FROM categories")
    categories = cur.fetchall()

    profile_data = []
    for cat in categories:
        # Check how many times the profile owner has voted in this category
        cur.execute("SELECT COUNT(*) as cnt FROM votes WHERE voter_id=? AND category_id=?", (user['id'], cat['id']))
        votes_count = cur.fetchone()['cnt']

        # Only show the rank if they have completed the required number of votes
        if votes_count >= MAX_VOTES:
            cur.execute("SELECT rating FROM elo_ratings WHERE user_id=? AND category_id=?", (user['id'], cat['id']))
            rating_row = cur.fetchone()
            rating = rating_row['rating'] if rating_row else 1200

            # Calculate the user's rank in this category
            cur.execute("""
                SELECT COUNT(*)+1 as rank
                FROM elo_ratings
                WHERE category_id=? AND rating > ?
            """, (cat['id'], rating))
            rank = cur.fetchone()['rank']

            profile_data.append({
                'category': cat['name'],
                'rating': round(rating, 1),
                'rank': rank
            })
        else:
            # If they haven't voted enough, the rank is locked
            profile_data.append({
                'category': cat['name'],
                'rating': None,
                'rank': None
            })

    cur.close()
    conn.close()

    # Render the user_profile template with all the necessary data
    return render_template('user_profile.html', user=user, profile_data=profile_data, viewer_gender=viewer_gender)

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

    return render_template('complete_profile.html')

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

    return render_template('select_gender.html')

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('landing'))

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, username, full_name, bio, gender FROM users WHERE id=?", (session['user_id'],))
    user = cur.fetchone()

    cur.execute("SELECT id, name FROM categories")
    categories = cur.fetchall()

    profile_data = []
    for cat in categories:
        cur.execute("SELECT COUNT(*) as cnt FROM votes WHERE voter_id=? AND category_id=?", (user['id'], cat['id']))
        votes_count = cur.fetchone()['cnt']

        if votes_count >= MAX_VOTES:
            cur.execute("SELECT rating FROM elo_ratings WHERE user_id=? AND category_id=?", (user['id'], cat['id']))
            rating_row = cur.fetchone()
            rating = rating_row['rating'] if rating_row else 1200

            cur.execute("""
                SELECT COUNT(*)+1 as rank
                FROM elo_ratings
                WHERE category_id=? 
                AND rating > (SELECT rating FROM elo_ratings WHERE user_id=? AND category_id=?)
            """, (cat['id'], user['id'], cat['id']))
            rank = cur.fetchone()['rank']

            profile_data.append({
                'category': cat['name'],
                'votes': votes_count,
                'rating': round(rating, 1),
                'rank': rank
            })
        else:
            profile_data.append({
                'category': cat['name'],
                'votes': votes_count,
                'rating': None,
                'rank': None
            })

    cur.close()
    conn.close()

    return render_template('profile.html', user=user, profile_data=profile_data, MAX_VOTES=MAX_VOTES)

@app.route('/category')
def category():
    if 'username' not in session:
        return redirect(url_for('landing'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch user's gender to pass to the template
    cur.execute("SELECT gender FROM users WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    user_gender = user['gender'] if user else 'male'
    
    cur.execute("SELECT id, name FROM categories")
    categories = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return render_template('category.html', categories=categories, gender=user_gender)

@app.route('/category/<int:cat_id>')
def category_page(cat_id):
    if 'user_id' not in session:
        return redirect(url_for('landing'))

    conn = get_db_connection()
    cur = conn.cursor()
    
    user_id = session['user_id']
    cur.execute("SELECT gender FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    user_gender = user['gender'] if user else 'male'

    cur.execute("SELECT id, name FROM categories WHERE id = ?", (cat_id,))
    category = cur.fetchone()
    if not category:
        cur.close()
        conn.close()
        return "Invalid category.", 404

    # Fetch current vote count for the progress bar
    cur.execute("SELECT COUNT(*) as cnt FROM votes WHERE voter_id=? AND category_id=?", (user_id, cat_id))
    votes_count = cur.fetchone()['cnt']

    cur.execute("""
        SELECT winner_id, loser_id 
        FROM votes 
        WHERE voter_id = ? AND category_id = ?
    """, (user_id, cat_id))
    voted_pairs_raw = cur.fetchall()
    
    voted_pairs = set()
    for pair in voted_pairs_raw:
        sorted_pair = tuple(sorted((pair['winner_id'], pair['loser_id'])))
        voted_pairs.add(sorted_pair)

    cur.execute("""
        SELECT u.id, u.username, u.full_name, u.gender, e.rating
        FROM users u
        JOIN elo_ratings e ON u.id = e.user_id
        WHERE e.category_id = ? AND u.id != ?
        ORDER BY RANDOM()
        LIMIT 20 
    """, (cat_id, user_id))
    
    potential_candidates = cur.fetchall()
    cur.close()
    conn.close()

    if len(potential_candidates) < 2:
        return "Not enough rated users in this category to vote.", 400

    candidates = None
    for p1, p2 in combinations(potential_candidates, 2):
        current_pair = tuple(sorted((p1['id'], p2['id'])))
        if current_pair not in voted_pairs:
            candidates = [p1, p2]
            break

    if not candidates:
        return render_template('all_voted.html', 
                               category=category, 
                               gender=user_gender)

    return render_template('vote.html', 
                           category=category, 
                           candidates=candidates, 
                           gender=user_gender,
                           votes_count=votes_count,
                           MAX_VOTES=MAX_VOTES)

@app.route('/vote', methods=['POST'])
def vote():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in.'}), 401

    data = request.get_json(silent=True) or {}
    try:
        winner_id = int(data.get('winner_id'))
        loser_id = int(data.get('loser_id'))
        category_id = int(data.get('category_id'))
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': 'Invalid payload.'}), 400

    if winner_id == loser_id:
        return jsonify({'status': 'error', 'message': 'Winner and loser cannot be the same.'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM categories WHERE id = ?", (category_id,))
        if not cur.fetchone():
            return jsonify({'status': 'error', 'message': 'Invalid category.'}), 404
        cur.execute("SELECT 1 FROM users WHERE id = ?", (winner_id,))
        if not cur.fetchone():
            return jsonify({'status': 'error', 'message': 'Invalid winner user.'}), 404
        cur.execute("SELECT 1 FROM users WHERE id = ?", (loser_id,))
        if not cur.fetchone():
            return jsonify({'status': 'error', 'message': 'Invalid loser user.'}), 404

        cur.execute("SELECT COUNT(*) as cnt FROM votes WHERE voter_id=? AND category_id=?",
                    (session['user_id'], category_id))
        votes_count = cur.fetchone()['cnt']
        if votes_count >= MAX_VOTES:
            return jsonify({'status': 'error', 'message': f'Max {MAX_VOTES} votes allowed per category.'}), 403

        cur.execute("INSERT OR IGNORE INTO elo_ratings (user_id, category_id, rating) VALUES (?, ?, 1200)", (winner_id, category_id))
        cur.execute("INSERT OR IGNORE INTO elo_ratings (user_id, category_id, rating) VALUES (?, ?, 1200)", (loser_id, category_id))

        cur.execute("SELECT rating FROM elo_ratings WHERE user_id=? AND category_id=?", (winner_id, category_id))
        wr = cur.fetchone()
        cur.execute("SELECT rating FROM elo_ratings WHERE user_id=? AND category_id=?", (loser_id, category_id))
        lr = cur.fetchone()

        if not wr or not lr:
            return jsonify({'status': 'error', 'message': 'Ratings not initialized.'}), 500

        winner_rating, loser_rating = float(wr['rating']), float(lr['rating'])
        K = 32
        expected_winner = 1.0 / (1.0 + 10 ** ((loser_rating - winner_rating) / 400.0))
        new_winner_rating = round(winner_rating + K * (1 - expected_winner), 1)
        new_loser_rating  = round(loser_rating  + K * (0 - (1 - expected_winner)), 1)

        cur.execute("UPDATE elo_ratings SET rating=? WHERE user_id=? AND category_id=?", (new_winner_rating, winner_id, category_id))
        cur.execute("UPDATE elo_ratings SET rating=? WHERE user_id=? AND category_id=?", (new_loser_rating, loser_id, category_id))
        cur.execute("INSERT INTO votes (voter_id, winner_id, loser_id, category_id, timestamp) VALUES (?, ?, ?, ?, datetime('now'))",
                    (session['user_id'], winner_id, loser_id, category_id))

        votes_count += 1
        conn.commit()

        return jsonify({
            'status': 'success',
            'message': 'Vote recorded',
            'votes_in_category': votes_count,
            'unlocked': votes_count >= MAX_VOTES
        })
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': f'Unexpected error: {e}'}), 500
    finally:
        cur.close()
        conn.close()
        
@app.route('/aboutus')
def aboutus_page():
    user_gender = 'male' 
    if 'user_id' in session:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT gender FROM users WHERE id = ?", (session['user_id'],))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user:
            user_gender = user['gender']
    return render_template('aboutus.html', gender=user_gender)

@app.route('/ascii')
def ascii_page():
    return render_template('ascii.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('landing'))

if __name__ == '__main__':
    app.run(debug=True)
