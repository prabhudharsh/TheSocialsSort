# The Social Sort 🚀

The Social Sort is a social ranking web application built with Python and Flask. It allows users within a closed community, like a college, to vote on and rank their peers in various categories using an Elo-based system. The platform is designed to be hyper-local, restricting voting matchups to users within the same class to create a more relevant and engaging experience.

-----

## Key Features ✨

  * **Elo Rating System**: Implements the Elo algorithm to provide a dynamic and fair ranking system where winning against a higher-ranked peer yields more points.
  * **Localized Voting**: Users are only compared with other members of their specific class and college, making the rankings highly contextual.
  * **Secure User Authentication**: Features a complete user registration system, including email verification via a One-Time Password (OTP) to ensure valid users.
  * **Profile Management**: Users can create profiles with a full name, bio, and college/class information after signing up.
  * **Engagement-Based Anonymity**: A user's rank and rating in a category are only revealed after they have cast a minimum of 10 votes, encouraging active participation.
  * **Comprehensive Admin Dashboard**: A password-protected area for administrators to manage users, colleges, classes, and voting categories.

-----

## How to Run the Project ⚙️

Follow these steps to get the application running on your local machine.

### 1\. Clone the Repository

First, clone the project repository to your local machine.

```bash
git clone https://github.com/prabhudharsh/TheSocialsSort
cd TheSocialsSort
```

### 2\. Create and Activate a Virtual Environment

It is highly recommended to use a virtual environment to manage project dependencies.

  * **Create the environment:**
    ```bash
    python -m venv env
    ```
  * **Activate the environment:**
      * On Windows: `env\Scripts\activate`
      * On macOS/Linux: `source env/bin/activate`

### 3\. Install Dependencies

Install all the required Python packages using the `requirements.txt` file.

```bash
pip install -r requirements.txt
```

*(Note: This file should contain packages like `Flask`, `python-dotenv`, `Werkzeug`, etc.)*

### 4\. Set Up Environment Variables

Create a file named `.env` in the root directory of the project. This file will store your secret keys and configuration variables. Populate it with the following:

```ini
# A strong, random string for Flask session security
SECRET_KEY='your_super_secret_key'

# The path to your SQLite database file
DB_PATH='database.db'

# Gmail account credentials for sending OTP emails
# Note: You may need to use an "App Password" for this to work
SENDER_EMAIL='your-email@gmail.com'
SENDER_PASSWORD='your_gmail_app_password'

# Credentials for the admin dashboard login
ADMIN_USERNAME='admin'
ADMIN_PASSWORD='your_secure_admin_password'
```

### 5\. Run the Application

Once the setup is complete, you can run the application. The script will automatically initialize the database if it doesn't exist.

```bash
python app.py
```

The application will now be running on `http://127.0.0.1:5000`. You can access it in your web browser.