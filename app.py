
import os, io, json, base64, sqlite3, hashlib
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import crypto_utils

app = Flask(__name__)
app.secret_key = os.urandom(32)
DB_PATH = "pki_users.db"

def get_db():
    db = sqlite3.connect(DB_PATH); db.row_factory = sqlite3.Row; return db

def init_db():
    db = get_db()
    db.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, organization TEXT NOT NULL, cert_serial TEXT NOT NULL, cert_fingerprint TEXT NOT NULL, registered_at TEXT NOT NULL, is_admin INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1)""")
    db.execute("""CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT NOT NULL, details TEXT, ip_address TEXT, timestamp TEXT NOT NULL, success INTEGER DEFAULT 1)""")
    db.execute("""CREATE TABLE IF NOT EXISTS signed_documents (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, filename TEXT NOT NULL, file_hash TEXT NOT NULL, signature_hex TEXT NOT NULL, signed_at TEXT NOT NULL)""")
    db.commit(); db.close()

def log_action(username, action, details="", ip="", success=True):
    db = get_db()
    db.execute("INSERT INTO audit_log (username,action,details,ip_address,timestamp,success) VALUES (?,?,?,?,?,?)", (username,action,details,ip,datetime.utcnow().isoformat(),1 if success else 0))
    db.commit(); db.close()

def login_required(f):
    @wraps(f)
    def d(*a,**k):
        if "username" not in session: flash("Please login first.","warning"); return redirect(url_for("login"))
        return f(*a,**k)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a,**k):
        if not session.get("is_admin"): flash("Admin required.","danger"); return redirect(url_for("dashboard"))
        return f(*a,**k)
    return d

@app.route("/")
def index(): return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username=request.form.get("username","").strip(); email=request.form.get("email","").strip()
        organization=request.form.get("organization","").strip(); p12_password=request.form.get("p12_password","")
        confirm=request.form.get("confirm_password","")
        if not all([username,email,organization,p12_password]): flash("All fields required.","danger"); return render_template("register.html")
        if p12_password!=confirm: flash("Passwords do not match.","danger"); return render_template("register.html")
        if len(p12_password)<8: flash("Password must be at least 8 characters.","danger"); return render_template("register.html")
        db=get_db()
        if db.execute("SELECT id FROM users WHERE username=? OR email=?",(username,email)).fetchone():
            flash("Username or email already exists.","danger"); db.close(); return render_template("register.html")
        try:
            p12_bytes,serial=crypto_utils.generate_user_credentials(username,email,organization,p12_password)
            from cryptography.hazmat.primitives.serialization import pkcs12 as p12m
            from cryptography.hazmat.primitives import hashes
            _,cert,_=p12m.load_key_and_certificates(p12_bytes,p12_password.encode(),default_backend())
            fp=cert.fingerprint(hashes.SHA256()).hex()
            db.execute("INSERT INTO users (username,email,organization,cert_serial,cert_fingerprint,registered_at) VALUES (?,?,?,?,?,?)",(username,email,organization,str(serial),fp,datetime.utcnow().isoformat()))
            db.commit(); db.close()
            log_action(username,"REGISTER",f"Cert serial: {serial}")
            session["pending_p12"]=base64.b64encode(p12_bytes).decode(); session["pending_username"]=username
            flash("Registration successful! Download your certificate bundle below.","success")
            return redirect(url_for("download_cert"))
        except Exception as e:
            db.close(); flash(f"Error: {str(e)}","danger")
    return render_template("register.html")

@app.route("/download-cert")
def download_cert():
    if not session.get("pending_p12"): return redirect(url_for("register"))
    return render_template("download_cert.html", username=session.get("pending_username"))

@app.route("/download-cert/file")
def download_cert_file():
    p12_b64=session.pop("pending_p12",None); username=session.pop("pending_username",None)
    if not p12_b64: return redirect(url_for("register"))
    return send_file(io.BytesIO(base64.b64decode(p12_b64)),mimetype="application/x-pkcs12",as_attachment=True,download_name=f"{username}_certificate.p12")

@app.route("/login", methods=["GET","POST"])
def login():
    if "username" in session: return redirect(url_for("dashboard"))
    if request.method == "POST":
        p12_file=request.files.get("p12_file"); p12_password=request.form.get("p12_password","")
        if not p12_file or not p12_password: flash("Certificate and password required.","danger"); return render_template("login.html")
        p12_data=p12_file.read()
        pk,cert=crypto_utils.load_p12(p12_data,p12_password)
        if cert is None:
            log_action("unknown","LOGIN_FAIL","Invalid P12 or wrong password",request.remote_addr,False)
            flash("Invalid certificate or wrong password.","danger"); return render_template("login.html")
        v=crypto_utils.validate_certificate(cert)
        if not v["valid"]:
            from cryptography.hazmat.primitives import hashes
            log_action(cert.subject.get_attributes_for_oid(__import__('cryptography').x509.oid.NameOID.COMMON_NAME)[0].value,"LOGIN_FAIL",v["reason"],request.remote_addr,False)
            flash(f"Certificate rejected: {v['reason']}","danger"); return render_template("login.html")
        challenge=crypto_utils.generate_challenge()
        sig=crypto_utils.sign_challenge(pk,challenge)
        if not crypto_utils.verify_challenge_signature(cert,challenge,sig):
            flash("Challenge-response failed.","danger"); return render_template("login.html")
        from cryptography.hazmat.primitives import hashes
        fp=cert.fingerprint(hashes.SHA256()).hex()
        db=get_db(); user=db.execute("SELECT * FROM users WHERE cert_fingerprint=?",(fp,)).fetchone(); db.close()
        if not user: flash("Certificate not registered.","danger"); return render_template("login.html")
        if not user["is_active"]: flash("Account deactivated.","danger"); return render_template("login.html")
        session["username"]=user["username"]; session["email"]=user["email"]
        session["organization"]=user["organization"]; session["is_admin"]=bool(user["is_admin"])
        session["cert_serial"]=user["cert_serial"]; session["cert_fingerprint"]=fp
        log_action(user["username"],"LOGIN_SUCCESS",f"Cert serial {user['cert_serial']}",request.remote_addr)
        flash(f"Welcome, {user['username']}! Authenticated via PKI certificate.","success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    log_action(session.get("username","?"),"LOGOUT"); session.clear()
    flash("Logged out securely.","info"); return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    db=get_db()
    logs=db.execute("SELECT * FROM audit_log WHERE username=? ORDER BY timestamp DESC LIMIT 10",(session["username"],)).fetchall()
    docs=db.execute("SELECT * FROM signed_documents WHERE username=? ORDER BY signed_at DESC LIMIT 5",(session["username"],)).fetchall()
    db.close(); return render_template("dashboard.html",logs=logs,signed_docs=docs)

@app.route("/sign", methods=["GET","POST"])
@login_required
def sign_document():
    if request.method == "POST":
        p12_file=request.files.get("p12_file"); p12_password=request.form.get("p12_password",""); doc_file=request.files.get("document")
        if not all([p12_file,p12_password,doc_file]): flash("All fields required.","danger"); return render_template("sign.html")
        pk,cert=crypto_utils.load_p12(p12_file.read(),p12_password)
        if cert is None: flash("Invalid certificate or password.","danger"); return render_template("sign.html")
        from cryptography.hazmat.primitives import hashes
        fp=cert.fingerprint(hashes.SHA256()).hex()
        if fp!=session["cert_fingerprint"]:
            log_action(session["username"],"SIGN_FAIL","Certificate mismatch",request.remote_addr,False)
            flash("Certificate does not belong to your account. Attempt logged.","danger"); return render_template("sign.html")
        doc_bytes=doc_file.read(); file_hash=hashlib.sha256(doc_bytes).hexdigest()
        sig=crypto_utils.sign_message(pk,doc_bytes); sig_hex=sig.hex()
        db=get_db()
        db.execute("INSERT INTO signed_documents (username,filename,file_hash,signature_hex,signed_at) VALUES (?,?,?,?,?)",(session["username"],doc_file.filename,file_hash,sig_hex,datetime.utcnow().isoformat()))
        db.commit(); db.close()
        log_action(session["username"],"SIGN_DOCUMENT",f"Signed: {doc_file.filename}")
        flash("Document signed successfully!","success")
        return render_template("sign.html",signed=True,filename=doc_file.filename,file_hash=file_hash,signature=sig_hex[:64]+"...")
    return render_template("sign.html")

@app.route("/verify", methods=["GET","POST"])
def verify_document():
    result=None
    if request.method == "POST":
        doc_file=request.files.get("document"); sig_hex=request.form.get("signature_hex","").strip(); cert_file=request.files.get("cert_file")
        if not all([doc_file,sig_hex,cert_file]): flash("All fields required.","danger"); return render_template("verify.html")
        try:
            doc_bytes=doc_file.read(); sig=bytes.fromhex(sig_hex)
            cert=x509.load_pem_x509_certificate(cert_file.read(),default_backend())
            v=crypto_utils.validate_certificate(cert)
            if not v["valid"]: result={"valid":False,"reason":f"Signer cert invalid: {v['reason']}"}
            else:
                ok=crypto_utils.verify_signature(cert,doc_bytes,sig)
                ci=crypto_utils.get_cert_info(cert)
                result={"valid":ok,"reason":"Signature valid — document is unmodified." if ok else "INVALID — document may have been tampered with.","signer":ci["common_name"],"org":ci["organization"],"until":ci["not_after"]}
        except Exception as e: result={"valid":False,"reason":str(e)}
    return render_template("verify.html",result=result)

@app.route("/encrypt", methods=["GET","POST"])
@login_required
def encrypt_page():
    result=None
    if request.method == "POST":
        plaintext=request.form.get("plaintext","").strip(); rc=request.files.get("recipient_cert")
        if not plaintext or not rc: flash("Message and recipient cert required.","danger"); return render_template("encrypt.html")
        try:
            cert=x509.load_pem_x509_certificate(rc.read(),default_backend())
            enc=crypto_utils.encrypt_message(cert,plaintext.encode())
            result={"encrypted_json":json.dumps(enc,indent=2),"recipient":crypto_utils.get_cert_info(cert)["common_name"]}
            log_action(session["username"],"ENCRYPT",f"For {result['recipient']}")
        except Exception as e: flash(str(e),"danger")
    return render_template("encrypt.html",result=result)

@app.route("/decrypt", methods=["GET","POST"])
@login_required
def decrypt_page():
    result=None
    if request.method == "POST":
        ej=request.form.get("encrypted_json","").strip(); p12_file=request.files.get("p12_file"); p12_pass=request.form.get("p12_password","")
        if not all([ej,p12_file,p12_pass]): flash("All fields required.","danger"); return render_template("decrypt.html")
        try:
            ed=json.loads(ej); pk,cert=crypto_utils.load_p12(p12_file.read(),p12_pass)
            if pk is None: flash("Invalid certificate or password.","danger"); return render_template("decrypt.html")
            pt=crypto_utils.decrypt_message(pk,ed); result={"plaintext":pt.decode()}
            log_action(session["username"],"DECRYPT","Message decrypted")
        except Exception as e: flash(str(e),"danger")
    return render_template("decrypt.html",result=result)

@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    db=get_db()
    users=db.execute("SELECT * FROM users ORDER BY registered_at DESC").fetchall()
    logs=db.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50").fetchall()
    revoked=crypto_utils.load_revoked_serials(); db.close()
    return render_template("admin.html",users=users,logs=logs,revoked=revoked)

@app.route("/admin/revoke/<int:uid>", methods=["POST"])
@login_required
@admin_required
def revoke_user(uid):
    db=get_db(); u=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if u:
        crypto_utils.revoke_certificate(int(u["cert_serial"]))
        db.execute("UPDATE users SET is_active=0 WHERE id=?",(uid,)); db.commit()
        log_action(session["username"],"REVOKE_CERT",f"Revoked: {u['username']}")
        flash(f"Certificate for {u['username']} revoked.","warning")
    db.close(); return redirect(url_for("admin_panel"))

@app.route("/ca-cert")
def download_ca_cert():
    return send_file(io.BytesIO(crypto_utils.get_ca_cert_pem().encode()),mimetype="application/x-pem-file",as_attachment=True,download_name="securecorp_ca.pem")

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    crypto_utils.initialize_ca(); init_db()
    db=get_db()
    if not db.execute("SELECT id FROM users WHERE is_admin=1").fetchone():
        p12b,serial=crypto_utils.generate_user_credentials("admin","admin@securecorp.np","SecureCorp","Admin@1234")
        from cryptography.hazmat.primitives.serialization import pkcs12 as p12m
        from cryptography.hazmat.primitives import hashes
        _,cert,_=p12m.load_key_and_certificates(p12b,b"Admin@1234",default_backend())
        fp=cert.fingerprint(hashes.SHA256()).hex()
        db.execute("INSERT INTO users (username,email,organization,cert_serial,cert_fingerprint,registered_at,is_admin) VALUES (?,?,?,?,?,?,1)",("admin","admin@securecorp.np","SecureCorp",str(serial),fp,datetime.utcnow().isoformat()))
        db.commit()
        with open("admin_certificate.p12","wb") as f: f.write(p12b)
    db.close()
    app.run(debug=False,host="127.0.0.1",port=5001)
