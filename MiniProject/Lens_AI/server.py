from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import bcrypt
import os
import time
import datetime
import socket
import database

app = Flask(__name__)
app.secret_key = "screensentry_secret_2026"

MAX_ATTEMPTS    = 3
LOCKOUT_MINUTES = 10
failed_attempts = {}
lockout_until   = {}

# ─── Generate self-signed SSL cert ────────────────────────────────────────────
def generate_ssl_cert():
    """Generate a self-signed SSL certificate if not already present."""
    cert_file = "cert.pem"
    key_file  = "key.pem"
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt
        import ipaddress

        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Get local IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Build certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"ScreenSentry"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ScreenSentry"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow())
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.IPAddress(ipaddress.IPv4Address(local_ip)),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        # Write cert and key
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        print("[SSL] Certificate generated successfully.")
    except Exception as e:
        print(f"[SSL] Could not generate cert: {e}")
        return None, None
    return cert_file, key_file

# ─── Auth helpers ─────────────────────────────────────────────────────────────
def verify_password(username, password):
    conn = database.get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT password_hash FROM admin_users WHERE username=?", (username,))
    row  = cur.fetchone()
    conn.close()
    return row and bcrypt.checkpw(password.encode(), row['password_hash'].encode())

def is_logged_in():
    return session.get('admin_logged_in') == True

def setup_default_admin():
    conn = database.get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM admin_users")
    if cur.fetchone()['c'] == 0:
        pw = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
        cur.execute("INSERT INTO admin_users (username, password_hash) VALUES (?,?)",
                    ("admin", pw))
        conn.commit()
    conn.close()

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    ip    = request.remote_addr

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Check lockout
        if ip in lockout_until and time.time() < lockout_until[ip]:
            rem   = int((lockout_until[ip] - time.time()) / 60) + 1
            error = f"Locked out. Try again in {rem} minute(s)."
        elif verify_password(username, password):
            failed_attempts[ip] = 0
            session['admin_logged_in'] = True
            session['username']        = username
            database.log_audit("Mobile Login", f"Login from {ip}")
            return redirect(url_for("dashboard"))
        else:
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            database.log_audit("Failed Mobile Login", f"Attempt {failed_attempts[ip]} from {ip}")
            if failed_attempts[ip] >= MAX_ATTEMPTS:
                lockout_until[ip] = time.time() + LOCKOUT_MINUTES * 60
                error = f"Too many attempts. Locked for {LOCKOUT_MINUTES} mins."
            else:
                left  = MAX_ATTEMPTS - failed_attempts[ip]
                error = f"Invalid credentials. {left} attempt(s) left."

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    database.log_audit("Mobile Logout", f"Logout: {session.get('username','?')}")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))
    stats = database.get_statistics()
    return render_template("dashboard.html", stats=stats)

@app.route("/evidence")
def evidence():
    if not is_logged_in():
        return redirect(url_for("login"))
    records = database.get_all_evidence()
    return render_template("evidence.html", records=records)

@app.route("/evidence/<int:eid>/status/<status>")
def update_status(eid, status):
    if not is_logged_in():
        return redirect(url_for("login"))
    database.update_evidence_status(eid, status)
    return redirect(url_for("evidence"))

@app.route("/evidence/<int:eid>/delete")
def delete_evidence(eid):
    if not is_logged_in():
        return redirect(url_for("login"))
    database.soft_delete_evidence(eid)
    return redirect(url_for("evidence"))

@app.route("/recycle")
def recycle():
    if not is_logged_in():
        return redirect(url_for("login"))
    records = database.get_deleted_evidence()
    return render_template("recycle.html", records=records)

@app.route("/recycle/<int:eid>/restore")
def restore(eid):
    if not is_logged_in():
        return redirect(url_for("login"))
    database.restore_evidence(eid)
    return redirect(url_for("recycle"))

@app.route("/recycle/<int:eid>/permanent")
def permanent_delete(eid):
    if not is_logged_in():
        return redirect(url_for("login"))
    database.permanent_delete_evidence(eid)
    return redirect(url_for("recycle"))

@app.route("/audit")
def audit():
    if not is_logged_in():
        return redirect(url_for("login"))
    logs = database.get_audit_logs(50)
    return render_template("audit.html", logs=logs)

@app.route("/image/<path:img_path>")
def serve_image(img_path):
    if not is_logged_in():
        return "", 403
    full = os.path.join(".evidence", os.path.basename(img_path))
    if os.path.exists(full):
        return send_file(full, mimetype="image/jpeg")
    return "", 404

@app.route("/api/stats")
def api_stats():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(database.get_statistics())

if __name__ == "__main__":
    database.init_database()
    setup_default_admin()

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    cert_file, key_file = generate_ssl_cert()

    print(f"\n{'='*52}")
    print(f"  ScreenSentry Mobile Admin")
    if cert_file:
        print(f"  Open on your phone: https://{local_ip}:5000")
        print(f"  (Accept the security warning on your phone)")
    else:
        print(f"  Open on your phone: http://{local_ip}:5000")
    print(f"  Default login → user: admin / pass: admin123")
    print(f"{'='*52}\n")

    if cert_file:
        app.run(host="0.0.0.0", port=5000, debug=False,
                ssl_context=(cert_file, key_file))
    else:
        app.run(host="0.0.0.0", port=5000, debug=False)
