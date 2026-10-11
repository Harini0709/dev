
from flask import Flask, request, redirect, url_for, render_template_string, session
import sqlite3
import re
import hashlib
import hmac
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_NAME = "users.db"


# ---------- DATABASE ----------
def get_db():
    connection = sqlite3.connect(DB_NAME)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """)


# ---------- PASSWORD SECURITY ----------
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        200000
    ).hex()

    return hashed, salt


# ---------- HTML ----------
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Login and Signup</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        * { box-sizing: border-box; }

        body {
            font-family: Arial, sans-serif;
            background: #eef2ff;
            margin: 0;
            padding: 25px;
            color: #1e293b;
        }

        h1 {
            text-align: center;
            color: #4338ca;
        }

        .pipeline {
            max-width: 700px;
            margin: 20px auto;
            padding: 15px;
            text-align: center;
            background: #e0e7ff;
            border-radius: 10px;
            line-height: 2;
        }

        .container {
            max-width: 430px;
            margin: 25px auto;
            padding: 25px;
            background: white;
            border-radius: 14px;
            box-shadow: 0 5px 20px #00000012;
        }

        h2 { color: #4338ca; }

        input {
            width: 100%;
            padding: 12px;
            margin: 8px 0 15px;
            border: 1px solid #cbd5e1;
            border-radius: 7px;
        }

        button {
            width: 100%;
            padding: 12px;
            color: white;
            background: #4f46e5;
            border: none;
            border-radius: 7px;
            cursor: pointer;
        }

        button:hover { background: #3730a3; }

        .message {
            padding: 12px;
            background: #fee2e2;
            color: #991b1b;
            border-radius: 7px;
            margin: 15px 0;
        }

        .success {
            background: #dcfce7;
            color: #166534;
        }

        a { color: #4338ca; }

        .hint {
            font-size: 13px;
            color: #64748b;
        }
    </style>
</head>

<body>
    <h1>Login / Signup Form</h1>

    <div class="pipeline">
        <b>FORM VALIDATION PIPELINE</b><br>
        User Input → Validation → Database Check
        → Authentication → Result
    </div>

    <div class="container">
        {% if mode == "signup" %}
            <h2>Create Account</h2>

            <form method="POST" action="/signup">
                <label>Full Name</label>
                <input type="text" name="name"
                       value="{{ name }}"
                       maxlength="60"
                       placeholder="Enter your name" required>

                <label>Email</label>
                <input type="email" name="email"
                       value="{{ email }}"
                       maxlength="254"
                       placeholder="Enter your email" required>

                <label>Password</label>
                <input type="password" name="password"
                       minlength="8"
                       placeholder="At least 8 characters" required>

                <label>Confirm Password</label>
                <input type="password" name="confirm_password"
                       minlength="8"
                       placeholder="Re-enter password" required>

                <p class="hint">
                    Use 8+ characters with uppercase, lowercase,
                    a number and a special character.
                </p>

                <button type="submit">Sign Up</button>
            </form>

            <p>Already registered? <a href="/login">Login</a></p>

        {% elif mode == "login" %}
            <h2>Login</h2>

            <form method="POST" action="/login">
                <label>Email</label>
                <input type="email" name="email"
                       value="{{ email }}"
                       maxlength="254"
                       placeholder="Enter your email" required>

                <label>Password</label>
                <input type="password" name="password"
                       placeholder="Enter your password" required>

                <button type="submit">Login</button>
            </form>

            <p>New user? <a href="/signup">Create an account</a></p>

        {% elif mode == "welcome" %}
            <h2>Welcome!</h2>
            <p>You are successfully logged in.</p>
            <p><b>Name:</b> {{ name }}</p>
            <p><b>Email:</b> {{ email }}</p>

            <form method="POST" action="/logout">
                <button type="submit">Logout</button>
            </form>
        {% endif %}

        {% if message %}
            <div class="message {{ 'success' if success else '' }}">
                {{ message }}
            </div>
        {% endif %}
    </div>
</body>
</html>
"""


def show_page(mode, message="", success=False, name="", email=""):
    return render_template_string(
        HTML,
        mode=mode,
        message=message,
        success=success,
        name=name,
        email=email
    )


# ---------- SIGNUP ----------
@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return show_page("signup")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not name or not email or not password or not confirm_password:
        return show_page("signup", "All fields are required.", name=name, email=email)

    if len(name) > 60 or not re.fullmatch(r"[A-Za-z][A-Za-z .'-]*", name):
        return show_page("signup", "Enter a valid name.", name=name, email=email)

    if len(email) > 254 or not re.fullmatch(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", email
    ):
        return show_page("signup", "Enter a valid email address.", name=name, email=email)

    if len(password) < 8 or len(password) > 128:
        return show_page("signup", "Password must be 8 to 128 characters.", name=name, email=email)

    if not re.search(r"[A-Z]", password):
        return show_page("signup", "Password needs an uppercase letter.", name=name, email=email)

    if not re.search(r"[a-z]", password):
        return show_page("signup", "Password needs a lowercase letter.", name=name, email=email)

    if not re.search(r"[0-9]", password):
        return show_page("signup", "Password needs a number.", name=name, email=email)

    if not re.search(r"[^A-Za-z0-9]", password):
        return show_page("signup", "Password needs a special character.", name=name, email=email)

    if password != confirm_password:
        return show_page("signup", "Passwords do not match.", name=name, email=email)

    try:
        password_hash, salt = hash_password(password)

        with get_db() as db:
            db.execute(
                "INSERT INTO users (name, email, password_hash, salt) VALUES (?, ?, ?, ?)",
                (name, email, password_hash, salt)
            )

        return show_page(
            "login",
            "Signup successful! Please log in.",
            success=True,
            email=email
        )

    except sqlite3.IntegrityError:
        return show_page(
            "signup",
            "This email is already registered. Please log in.",
            name=name,
            email=email
        )


# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return show_page("login")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return show_page("login", "Enter both email and password.", email=email)

    try:
        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user is None:
            return show_page("login", "Invalid email or password.", email=email)

        entered_hash, _ = hash_password(password, user["salt"])

        if not hmac.compare_digest(entered_hash, user["password_hash"]):
            return show_page("login", "Invalid email or password.", email=email)

        session.clear()
        session["user_id"] = user["id"]

        return redirect(url_for("dashboard"))

    except sqlite3.Error:
        return show_page("login", "Database error. Please try again.", email=email)


# ---------- DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if not user_id:
        return redirect(url_for("login"))

    with get_db() as db:
        user = db.execute(
            "SELECT id, name, email FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return show_page(
        "welcome",
        success=True,
        name=user["name"],
        email=user["email"]
    )


# ---------- LOGOUT ----------
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    print("Login and Signup application started.")
    print("Open http://127.0.0.1:5000")
    app.run(debug=False)
