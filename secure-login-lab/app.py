"""
SSE M.Tech Lab 1 — Secure Login with bcrypt, Rate Limiting & TOTP 2FA
======================================================================
Run:  python app.py
Open: http://127.0.0.1:5000
"""

from flask import Flask, render_template, request, redirect, session, flash
import bcrypt, sqlite3, pyotp, qrcode
import time, os
from functools import wraps

app = Flask(__name__)
app.secret_key = "change-this-in-production"

DB = "users.db"

# ── Replay-attack prevention: stores last used OTP per user (in-memory) ──
used_otps: dict[str, str] = {}

# ─────────────────────────── DATABASE ───────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row          # access columns by name
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username        TEXT PRIMARY KEY,
            password        BLOB,           -- bcrypt hash (never plaintext)
            otp_secret      TEXT,           -- Base32 TOTP secret
            failed_attempts INTEGER DEFAULT 0,
            locked_until    REAL    DEFAULT 0   -- Unix timestamp
        )
    """)
    conn.commit()
    conn.close()

def get_user(username: str):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return user

# ─────────────────────────── DECORATOR ───────────────────────────
def login_required(f):
    """Redirect unauthenticated users to the login page."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            flash("Please log in first.", "error")
            return redirect("/")
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────── REGISTER ───────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            flash("Both fields are required.", "error")
            return render_template("register.html")

        # Hash password with bcrypt (auto-generates a random salt)
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        # Generate a random Base32 TOTP secret for this user
        secret = pyotp.random_base32()

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, 0, 0)",
                (username, hashed, secret)
            )
            conn.commit()
            conn.close()
            flash("Account created! Please log in.", "success")
            return redirect("/")
        except sqlite3.IntegrityError:
            flash("Username already taken.", "error")

    return render_template("register.html")

# ─────────────────────────── LOGIN ───────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = get_user(username)

        if not user:
            flash("Invalid credentials.", "error")
            return render_template("login.html")

        # ── ACCOUNT LOCKOUT CHECK ──
        if time.time() < user["locked_until"]:
            secs = int(user["locked_until"] - time.time())
            flash(f"Account locked. Try again in {secs}s.", "error")
            return render_template("login.html")

        # ── PASSWORD CHECK ──
        if bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            # Success: clear failed count and proceed to 2FA
            conn = get_db()
            conn.execute(
                "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
                (username,)
            )
            conn.commit()
            conn.close()
            session.clear()
            session["user"] = username
            session["2fa_ok"] = False
            return redirect("/2fa")
        else:
            # ── RATE LIMITING: track failures, lock after 5 ──
            attempts = user["failed_attempts"] + 1
            lock_time = 0

            if attempts >= 5:
                lock_time = time.time() + 60   # lock for 60 seconds
                attempts = 0
                flash("Too many failed attempts. Account locked for 60 seconds.", "error")
            else:
                flash(f"Wrong password. {5 - attempts} attempt(s) remaining.", "error")

            conn = get_db()
            conn.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                (attempts, lock_time, username)
            )
            conn.commit()
            conn.close()

    return render_template("login.html")

# ─────────────────────────── 2FA ─────────────────────────────────
@app.route("/2fa")
@login_required
def twofa():
    username = session["user"]
    user = get_user(username)
    secret = user["otp_secret"]

    # Build provisioning URI and render QR code
    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(name=username, issuer_name="SecureLab")

    os.makedirs("static", exist_ok=True)
    qrcode.make(uri).save("static/qr.png")

    return render_template("twofa.html", username=username)

@app.route("/verify", methods=["POST"])
@login_required
def verify():
    otp      = request.form["otp"].strip()
    username = session["user"]
    user     = get_user(username)
    secret   = user["otp_secret"]
    totp     = pyotp.TOTP(secret)

    # ── REPLAY ATTACK PREVENTION ──
    # If the same OTP was already accepted in this 30-second window, reject it
    if used_otps.get(username) == otp:
        flash("OTP already used. Wait for the next code.", "error")
        return redirect("/2fa")

    if totp.verify(otp, valid_window=0):    # valid_window=0 → strict, no clock drift
        used_otps[username] = otp           # mark as consumed
        session["2fa_ok"] = True
        return redirect("/dashboard")
    else:
        flash("Invalid OTP. Please try again.", "error")
        return redirect("/2fa")

# ─────────────────────────── DASHBOARD ───────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    if not session.get("2fa_ok"):
        flash("Complete 2FA first.", "error")
        return redirect("/2fa")
    return render_template("dashboard.html", username=session["user"])

# ─────────────────────────── LOGOUT ──────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect("/")

# ─────────────────────────── ADMIN VIEW ──────────────────────────
@app.route("/admin/db")
def view_db():
    """
    Dev-only route — lets you see the raw DB contents to verify
    passwords are stored as bcrypt hashes (never plaintext).
    Remove this route before deploying to production!
    """
    conn = get_db()
    users = conn.execute(
        "SELECT username, password, failed_attempts, locked_until FROM users"
    ).fetchall()
    conn.close()
    return render_template("db_view.html", users=users)

# ─────────────────────────── MAIN ────────────────────────────────
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
