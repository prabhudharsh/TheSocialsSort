import os
import random
import mysql.connector
from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify
from dotenv import load_dotenv
import smtplib

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME')
    )

def send_otp_via_email(user_email, otp_code):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASSWORD')


    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp_code}"

    message = f"Subject: {subject}\n\n{body}"

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, user_email, message)
        server.quit()
        print("OTP sent successfully.")
    except Exception as e:
        print("Error sending email:", e)

@app.route('/')
def home():
    return redirect(url_for('landing'))

@app.route('/landing')
def landing():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        otp = str(random.randint(100000, 999999))
        session['pending_user'] = {
            'username': username,
            'email': email,
            'password': password,
            'otp': otp
        }

        send_otp_via_email(email, otp)
        flash("OTP sent to your email. Please verify.", "info")
        return redirect(url_for('verify_otp'))

    return render_template('signup.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_user' not in session:
        flash("Please sign up first.", "warning")
        return redirect(url_for('signup'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['pending_user']['otp']:
            user = session['pending_user']
            conn = get_db_connection()
            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO users (username, email, password, is_verified) VALUES (%s, %s, %s, %s)",
                    (user['username'], user['email'], user['password'], True)
                )
                conn.commit()
                flash("Email verified! You can now login.", "success")
            except mysql.connector.Error as err:
                flash(f"Database error: {err}", "danger")
                return redirect(url_for('signup'))
            finally:
                cur.close()
                conn.close()
            session.pop('pending_user')
            return redirect(url_for('login'))
        else:
            flash("Invalid OTP, please try again.", "danger")

    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password, is_verified FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and user[1] == password_input:
            if not user[2]:
                flash("Please verify your email first.", "warning")
                return redirect(url_for('login'))
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT username, name, bio FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    return render_template('dashboard.html', username=user['username'])

@app.route('/complete_profile', methods=['GET', 'POST'])
def complete_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        bio = request.form['bio']

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET name = %s, bio = %s WHERE id = %s",
            (name, bio, session['user_id'])
        )
        conn.commit()
        cur.close()
        conn.close()

        flash('Profile updated! Please pick your gender.', 'info')
        return redirect(url_for('pick_gender'))

    return render_template('complete_profile.html')

@app.route('/pick_gender', methods=['GET', 'POST'])
def pick_gender():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        gender = request.form['gender']  # Male or Female
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET gender = %s WHERE id = %s",
            (gender, session['user_id'])
        )
        conn.commit()
        cur.close()
        conn.close()

        flash('Gender saved successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('pick_gender.html')

@app.route('/profile/<username>')
def profile(username):
    if 'username' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT username, name, bio FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('profile.html', user=user)


if __name__ == '__main__':
    app.run(debug=True)