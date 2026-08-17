import os, sqlite3, hashlib, base64, secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "exam_security.db")
STORAGE = os.path.join(BASE, "storage")
os.makedirs(STORAGE, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "prototype-change-this-secret")
ALLOWED = {"pdf", "docx", "txt"}

def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS papers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        encrypted_file TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        uploaded_by TEXT NOT NULL,
        uploaded_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        paper_id INTEGER,
        status TEXT NOT NULL,
        ip TEXT,
        created_at TEXT NOT NULL
    );
    """)
    if not con.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        con.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                    ("admin", generate_password_hash("admin123"), "admin"))
    if not con.execute("SELECT 1 FROM users WHERE username='staff'").fetchone():
        con.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                    ("staff", generate_password_hash("staff123"), "staff"))
    con.commit()
    con.close()

def get_key():
    # Prototype key. For a real deployment, keep the AES key in a secrets manager/HSM,
    # not in source code.
    key_file = os.path.join(BASE, ".aes_key")
    if not os.path.exists(key_file):
        with open(key_file, "wb") as f:
            f.write(AESGCM.generate_key(bit_length=256))
    return open(key_file, "rb").read()

def encrypt_bytes(data):
    key = get_key()
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aes.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_bytes(blob):
    key = get_key()
    aes = AESGCM(key)
    return aes.decrypt(blob[:12], blob[12:], None)

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def log_action(username, action, paper_id=None, status="SUCCESS"):
    con = db()
    con.execute(
        "INSERT INTO logs(username,action,paper_id,status,ip,created_at) VALUES(?,?,?,?,?,?)",
        (username, action, paper_id, status, request.remote_addr or "local",
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    con.commit()
    con.close()

def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("Access denied.", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapper
    return deco

@app.route("/")
def home():
    return redirect(url_for("dashboard") if "username" in session else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        con = db()
        user = con.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        con.close()

        if user and check_password_hash(user["password"], password):

            # Generate a 6-digit OTP
            otp = str(secrets.randbelow(900000) + 100000)

            # Store temporary login information
            session["pending_username"] = user["username"]
            session["pending_role"] = user["role"]
            session["otp"] = otp
            session["otp_expires"] = (
                datetime.now() + timedelta(minutes=5)
            ).timestamp()

            # For prototype demonstration only:
            print("\n===================================")
            print("        UNISHIELD OTP")
            print("===================================")
            print("User:", user["username"])
            print("OTP:", otp)
            print("Valid for 5 minutes")
            print("===================================\n")

            flash("Password verified. Enter the OTP.", "success")
            return redirect(url_for("verify_otp"))

        log_action(username or "unknown", "LOGIN", status="FAILED")
        flash("Invalid username or password.", "danger")

    return render_template("login.html")
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():

    if "pending_username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        entered_otp = request.form["otp"].strip()

        # Check OTP expiry
        if datetime.now().timestamp() > session.get("otp_expires", 0):
            flash("OTP has expired. Please login again.", "danger")
            session.clear()
            return redirect(url_for("login"))

        # Verify OTP
        if entered_otp == session.get("otp"):

            username = session["pending_username"]
            role = session["pending_role"]

            # Complete login
            session.pop("otp", None)
            session.pop("otp_expires", None)
            session.pop("pending_username", None)
            session.pop("pending_role", None)

            session["username"] = username
            session["role"] = role

            log_action(username, "LOGIN + OTP VERIFICATION")
            flash("OTP verified. Login successful.", "success")

            return redirect(url_for("dashboard"))

        else:
            log_action(
                session.get("pending_username", "unknown"),
                "OTP VERIFICATION FAILED",
                status="FAILED"
            )
            flash("Invalid OTP. Access denied.", "danger")

    return render_template("otp.html")

@app.route("/logout")
def logout():
    if "username" in session:
        log_action(session["username"], "LOGOUT")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required()
def dashboard():
    con = db()
    papers = con.execute("SELECT * FROM papers ORDER BY id DESC").fetchall()
    recent_logs = con.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 8").fetchall()
    con.close()
    return render_template("dashboard.html", papers=papers, logs=recent_logs)

@app.route("/upload", methods=["POST"])
@login_required("admin")
def upload():
    file = request.files.get("paper")
    if not file or not file.filename:
        flash("Choose a question paper.", "danger")
        return redirect(url_for("dashboard"))
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED:
        flash("Prototype accepts PDF, DOCX, or TXT files.", "danger")
        return redirect(url_for("dashboard"))

    original = file.read()
    digest = sha256_bytes(original)
    encrypted = encrypt_bytes(original)

    safe = secure_filename(file.filename)
    stored_name = f"{secrets.token_hex(8)}_{safe}.enc"
    with open(os.path.join(STORAGE, stored_name), "wb") as f:
        f.write(encrypted)

    con = db()
    cur = con.execute(
        "INSERT INTO papers(filename,encrypted_file,sha256,uploaded_by,uploaded_at) VALUES(?,?,?,?,?)",
        (safe, stored_name, digest, session["username"],
         datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    paper_id = cur.lastrowid
    con.commit()
    con.close()
    log_action(session["username"], "UPLOAD + AES ENCRYPTION + SHA-256", paper_id)
    flash("Question paper encrypted and stored securely.", "success")
    return redirect(url_for("dashboard"))

@app.route("/download/<int:paper_id>")
@login_required()
def download(paper_id):
    con = db()
    paper = con.execute("SELECT * FROM papers WHERE id=?", (paper_id,)).fetchone()
    con.close()
    if not paper:
        flash("Paper not found.", "danger")
        return redirect(url_for("dashboard"))

    # Simple prototype access control: staff/admin only after login.
    # Production version should also enforce scheduled exam time and per-paper permissions.
    try:
        with open(os.path.join(STORAGE, paper["encrypted_file"]), "rb") as f:
            decrypted = decrypt_bytes(f.read())
    except Exception:
        log_action(session["username"], "DECRYPTION FAILED", paper_id, "FAILED")
        flash("Unable to decrypt the paper.", "danger")
        return redirect(url_for("dashboard"))

    current_hash = sha256_bytes(decrypted)
    if current_hash != paper["sha256"]:
        log_action(session["username"], "SHA-256 VERIFICATION FAILED", paper_id, "ALERT")
        flash("Integrity check failed: possible tampering detected.", "danger")
        return redirect(url_for("dashboard"))

    # Leak/suspicious-activity demo: more than 3 accesses to the same paper in 5 minutes.
    con = db()
    since = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    count = con.execute(
        "SELECT COUNT(*) FROM logs WHERE username=? AND paper_id=? AND action='PAPER ACCESS' AND created_at>=?",
        (session["username"], paper_id, since)
    ).fetchone()[0]
    con.close()

    status = "SUCCESS"
    action = "PAPER ACCESS"
    if count >= 3:
        status = "ALERT"
        action = "SUSPICIOUS ACCESS / LEAK ALERT"
        flash("Suspicious repeated access detected. Admin alert generated.", "danger")
    log_action(session["username"], action, paper_id, status)

    from io import BytesIO
    return send_file(BytesIO(decrypted), as_attachment=True, download_name=paper["filename"])

@app.route("/logs")
@login_required("admin")
def logs():
    con = db()
    rows = con.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
    con.close()
    return render_template("logs.html", logs=rows)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)