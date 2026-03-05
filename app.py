"""
app.py - SecureCorp PKI Login System
A Flask web application demonstrating PKI-based authentication,
digital signatures, hybrid encryption, and certificate management.
"""

import os
import io
import json
import base64
import sqlite3
import hashlib
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, send_file, jsonify, g)
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import crypto_utils

app = Flask(__name__)
app.secret_key = os.urandom(32)

DB_PATH = "pki_users.db"
CHALLENGES = {}  # In-memory challenge store (use Redis in production)

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        organization TEXT NOT NULL,
        cert_serial TEXT NOT NULL,
        cert_fingerprint TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TEXT NOT NULL,
        success INTEGER DEFAULT 1
    )""")
    db.execute("""CREATE TABLE IF NOT EXISTS signed_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        filename TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        signature_hex TEXT NOT NULL,
        signed_at TEXT NOT NULL
    )""")
    db.commit()
    db.close()

def log_action(username, action, details="", ip="", success=True):
    db = get_db()
    db.execute("INSERT INTO audit_log (username, action, details, ip_address, timestamp, success) VALUES (?,?,?,?,?,?)",
        (username, action, details, ip, datetime.utcnow().isoformat(), 1 if success else 0))
    db.commit()
    db.close()

# ─────────────────────────────────────────────
# Auth Decorator
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            flash("Please login with your certificate to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session or not session.get("is_admin"):
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        organization = request.form.get("organization", "").strip()
        p12_password = request.form.get("p12_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([username, email, organization, p12_password]):
            flash("All fields are required.", "danger")
            return render_template("register.html")

        if p12_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        if len(p12_password) < 8:
            flash("Certificate password must be at least 8 characters.", "danger")
            return render_template("register.html")

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username=? OR email=?", (username, email)).fetchone()
        if existing:
            flash("Username or email already registered.", "danger")
            db.close()
            return render_template("register.html")

        try:
            p12_bytes, serial = crypto_utils.generate_user_credentials(username, email, organization, p12_password)

            # Load cert to extract fingerprint
            from cryptography.hazmat.primitives.serialization import pkcs12 as p12mod
            _, cert, _ = p12mod.load_key_and_certificates(p12_bytes, p12_password.encode(), default_backend())
            from cryptography.hazmat.primitives import hashes
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()

            db.execute("INSERT INTO users (username, email, organization, cert_serial, cert_fingerprint, registered_at) VALUES (?,?,?,?,?,?)",
                (username, email, organization, str(serial), fingerprint, datetime.utcnow().isoformat()))
            db.commit()
            db.close()

            log_action(username, "REGISTER", f"Certificate issued. Serial: {serial}")

            session["pending_p12"] = base64.b64encode(p12_bytes).decode()
            session["pending_username"] = username
            flash(f"Registration successful! Download your certificate bundle (.p12) below. Keep it safe — you need it to login.", "success")
            return redirect(url_for("download_cert"))
        except Exception as e:
            db.close()
            flash(f"Registration failed: {str(e)}", "danger")

    return render_template("register.html")

@app.route("/download-cert")
def download_cert():
    p12_b64 = session.get("pending_p12")
    username = session.get("pending_username")
    if not p12_b64:
        return redirect(url_for("register"))
    return render_template("download_cert.html", username=username)

@app.route("/download-cert/file")
def download_cert_file():
    p12_b64 = session.pop("pending_p12", None)
    username = session.pop("pending_username", None)
    if not p12_b64:
        return redirect(url_for("register"))
    p12_bytes = base64.b64decode(p12_b64)
    return send_file(
        io.BytesIO(p12_bytes),
        mimetype="application/x-pkcs12",
        as_attachment=True,
        download_name=f"{username}_certificate.p12"
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if "username" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        p12_file = request.files.get("p12_file")
        p12_password = request.form.get("p12_password", "")

        if not p12_file or not p12_password:
            flash("Please provide your certificate file and password.", "danger")
            return render_template("login.html")

        p12_data = p12_file.read()
        private_key, cert = crypto_utils.load_p12(p12_data, p12_password)

        if cert is None:
            log_action("unknown", "LOGIN_FAIL", "Invalid P12 or wrong password", request.remote_addr, False)
            flash("Invalid certificate or wrong password.", "danger")
            return render_template("login.html")

        # Validate certificate
        validation = crypto_utils.validate_certificate(cert)
        if not validation["valid"]:
            cert_info = crypto_utils.get_cert_info(cert)
            log_action(cert_info.get("common_name","?"), "LOGIN_FAIL", validation["reason"], request.remote_addr, False)
            flash(f"Certificate rejected: {validation['reason']}", "danger")
            return render_template("login.html")

        # Challenge-response: sign a challenge with the private key, verify with cert
        challenge = crypto_utils.generate_challenge()
        signature = crypto_utils.sign_challenge(private_key, challenge)
        verified = crypto_utils.verify_challenge_signature(cert, challenge, signature)

        if not verified:
            flash("Challenge-response authentication failed. Key mismatch.", "danger")
            return render_template("login.html")

        # Look up user in database
        from cryptography.hazmat.primitives import hashes
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE cert_fingerprint=?", (fingerprint,)).fetchone()
        db.close()

        if not user:
            flash("Certificate not registered in the system.", "danger")
            return render_template("login.html")

        if not user["is_active"]:
            flash("Your account has been deactivated.", "danger")
            return render_template("login.html")

        # Successful login
        session["username"] = user["username"]
        session["email"] = user["email"]
        session["organization"] = user["organization"]
        session["is_admin"] = bool(user["is_admin"])
        session["cert_serial"] = user["cert_serial"]
        session["cert_fingerprint"] = fingerprint

        log_action(user["username"], "LOGIN_SUCCESS", f"PKI auth via cert serial {user['cert_serial']}", request.remote_addr)
        flash(f"Welcome back, {user['username']}! Authenticated via PKI certificate.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    log_action(username, "LOGOUT")
    session.clear()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    logs = db.execute("SELECT * FROM audit_log WHERE username=? ORDER BY timestamp DESC LIMIT 10",
        (session["username"],)).fetchall()
    signed_docs = db.execute("SELECT * FROM signed_documents WHERE username=? ORDER BY signed_at DESC LIMIT 5",
        (session["username"],)).fetchall()
    db.close()
    return render_template("dashboard.html", logs=logs, signed_docs=signed_docs)

@app.route("/sign", methods=["GET", "POST"])
@login_required
def sign_document():
    if request.method == "POST":
        p12_file = request.files.get("p12_file")
        p12_password = request.form.get("p12_password", "")
        doc_file = request.files.get("document")

        if not all([p12_file, p12_password, doc_file]):
            flash("All fields required: certificate, password, and document.", "danger")
            return render_template("sign.html")

        p12_data = p12_file.read()
        private_key, cert = crypto_utils.load_p12(p12_data, p12_password)

        if cert is None:
            flash("Invalid certificate or wrong password.", "danger")
            return render_template("sign.html")

        # Verify cert belongs to logged-in user
        from cryptography.hazmat.primitives import hashes
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        if fingerprint != session["cert_fingerprint"]:
            log_action(session["username"], "SIGN_FAIL", "Certificate mismatch — unauthorized signing attempt", request.remote_addr, False)
            flash("Certificate does not belong to your account. Unauthorized signing attempt logged.", "danger")
            return render_template("sign.html")

        doc_bytes = doc_file.read()
        file_hash = hashlib.sha256(doc_bytes).hexdigest()
        signature = crypto_utils.sign_message(private_key, doc_bytes)
        sig_hex = signature.hex()

        db = get_db()
        db.execute("INSERT INTO signed_documents (username, filename, file_hash, signature_hex, signed_at) VALUES (?,?,?,?,?)",
            (session["username"], doc_file.filename, file_hash, sig_hex, datetime.utcnow().isoformat()))
        db.commit()
        db.close()

        log_action(session["username"], "SIGN_DOCUMENT", f"Signed: {doc_file.filename} | SHA-256: {file_hash}")
        flash(f"Document signed successfully!", "success")
        return render_template("sign.html", signed=True, filename=doc_file.filename,
                               file_hash=file_hash, signature=sig_hex[:64]+"...")

    return render_template("sign.html")

@app.route("/verify", methods=["GET", "POST"])
def verify_document():
    result = None
    if request.method == "POST":
        doc_file = request.files.get("document")
        sig_hex = request.form.get("signature_hex", "").strip()
        cert_file = request.files.get("cert_file")

        if not all([doc_file, sig_hex, cert_file]):
            flash("All fields required: document, signature, and signer's certificate.", "danger")
            return render_template("verify.html")

        try:
            doc_bytes = doc_file.read()
            signature = bytes.fromhex(sig_hex)
            cert_pem = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

            # Validate the cert itself first
            validation = crypto_utils.validate_certificate(cert)
            if not validation["valid"]:
                result = {"valid": False, "reason": f"Signer's certificate is invalid: {validation['reason']}"}
            else:
                sig_valid = crypto_utils.verify_signature(cert, doc_bytes, signature)
                cert_info = crypto_utils.get_cert_info(cert)
                result = {
                    "valid": sig_valid,
                    "reason": "Signature is valid and document is unmodified." if sig_valid else "Signature verification failed. Document may have been tampered with.",
                    "signer": cert_info["common_name"],
                    "org": cert_info["organization"],
                    "cert_valid_until": cert_info["not_after"],
                }
        except Exception as e:
            result = {"valid": False, "reason": f"Verification error: {str(e)}"}

    return render_template("verify.html", result=result)

@app.route("/encrypt", methods=["GET", "POST"])
@login_required
def encrypt_page():
    result = None
    if request.method == "POST":
        plaintext = request.form.get("plaintext", "").strip()
        recipient_cert_file = request.files.get("recipient_cert")

        if not plaintext or not recipient_cert_file:
            flash("Message and recipient certificate required.", "danger")
            return render_template("encrypt.html")

        try:
            cert_pem = recipient_cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
            encrypted = crypto_utils.encrypt_message(cert, plaintext.encode())
            result = {
                "encrypted_json": json.dumps(encrypted, indent=2),
                "recipient": crypto_utils.get_cert_info(cert)["common_name"]
            }
            log_action(session["username"], "ENCRYPT", f"Message encrypted for {result['recipient']}")
        except Exception as e:
            flash(f"Encryption failed: {str(e)}", "danger")

    return render_template("encrypt.html", result=result)

@app.route("/decrypt", methods=["GET", "POST"])
@login_required
def decrypt_page():
    result = None
    if request.method == "POST":
        encrypted_json = request.form.get("encrypted_json", "").strip()
        p12_file = request.files.get("p12_file")
        p12_password = request.form.get("p12_password", "")

        if not all([encrypted_json, p12_file, p12_password]):
            flash("All fields required.", "danger")
            return render_template("decrypt.html")

        try:
            encrypted_data = json.loads(encrypted_json)
            p12_data = p12_file.read()
            private_key, cert = crypto_utils.load_p12(p12_data, p12_password)

            if private_key is None:
                flash("Invalid certificate or wrong password.", "danger")
                return render_template("decrypt.html")

            plaintext = crypto_utils.decrypt_message(private_key, encrypted_data)
            result = {"plaintext": plaintext.decode()}
            log_action(session["username"], "DECRYPT", "Message decrypted successfully")
        except Exception as e:
            flash(f"Decryption failed: {str(e)}", "danger")

    return render_template("decrypt.html", result=result)

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY registered_at DESC").fetchall()
    logs = db.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50").fetchall()
    revoked = crypto_utils.load_revoked_serials()
    db.close()
    return render_template("admin.html", users=users, logs=logs, revoked=revoked)

@app.route("/admin/revoke/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def revoke_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if user:
        crypto_utils.revoke_certificate(int(user["cert_serial"]))
        db.execute("UPDATE users SET is_active=0 WHERE id=?", (user_id,))
        db.commit()
        log_action(session["username"], "REVOKE_CERT", f"Revoked certificate for user: {user['username']}")
        flash(f"Certificate for {user['username']} has been revoked.", "warning")
    db.close()
    return redirect(url_for("admin_panel"))

@app.route("/ca-cert")
def download_ca_cert():
    ca_pem = crypto_utils.get_ca_cert_pem()
    return send_file(
        io.BytesIO(ca_pem.encode()),
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name="securecorp_ca.pem"
    )

@app.route("/api/cert-info", methods=["POST"])
def api_cert_info():
    cert_file = request.files.get("cert_file")
    if not cert_file:
        return jsonify({"error": "No certificate provided"}), 400
    try:
        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        info = crypto_utils.get_cert_info(cert)
        validation = crypto_utils.validate_certificate(cert)
        info["validation"] = validation
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ─────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    crypto_utils.initialize_ca()
    init_db()

    # Create a default admin user if none exists
    db = get_db()
    admin = db.execute("SELECT id FROM users WHERE is_admin=1").fetchone()
    if not admin:
        p12_bytes, serial = crypto_utils.generate_user_credentials(
            "admin", "admin@securecorp.np", "SecureCorp", "Admin@1234")
        from cryptography.hazmat.primitives.serialization import pkcs12 as p12mod
        from cryptography.hazmat.primitives import hashes
        _, cert, _ = p12mod.load_key_and_certificates(p12_bytes, b"Admin@1234", default_backend())
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        db.execute("INSERT INTO users (username, email, organization, cert_serial, cert_fingerprint, registered_at, is_admin) VALUES (?,?,?,?,?,?,1)",
            ("admin", "admin@securecorp.np", "SecureCorp", str(serial), fingerprint, datetime.utcnow().isoformat()))
        db.commit()
        # Save admin p12 for demo
        with open("admin_certificate.p12", "wb") as f:
            f.write(p12_bytes)
        print("[INIT] Admin certificate saved to admin_certificate.p12 (password: Admin@1234)")
    db.close()

    print("[INFO] SecureCorp PKI Login System running at http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
