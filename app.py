# app.py
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    send_from_directory, send_file
)
import mysql.connector
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.secret_key = "replace_with_a_strong_secret_here"  # change this for production

# ---------------------------
# Config & folders
# ---------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
CERT_FOLDER = os.path.join(BASE_DIR, "static", "certificates")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CERT_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["CERT_FOLDER"] = CERT_FOLDER

# ---------------------------
# DB helper (mysql.connector)
# ---------------------------
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="database_ewaste"
        # add auth_plugin="mysql_native_password" if your MySQL needs it
    )

# ---------------------------
# Small helpers
# ---------------------------
def save_profile_pic(file_obj):
    if not file_obj or file_obj.filename == "":
        return None
    filename = secure_filename(file_obj.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file_obj.save(path)
    return filename

def generate_certificate_pdf(pickup_id, title, issued_to, ewaste_type, center_name=None, agent_name=None):
    """
    Generic PDF generator. Returns filename (not path).
    filename stored in DB should be this return value.
    """
    filename = f"certificate_{title}_{pickup_id}.pdf"  # title: handover or recycle
    filepath = os.path.join(app.config["CERT_FOLDER"], filename)

    c = canvas.Canvas(filepath, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(width/2, height-90, "Certificate of E-Waste Handling")

    c.setFont("Helvetica", 12)
    y = height - 140
    c.drawCentredString(width/2, y, f"Pickup ID: {pickup_id}")
    y -= 18
    c.drawCentredString(width/2, y, f"Certificate Type: {title.capitalize()}")
    y -= 22
    c.drawCentredString(width/2, y, f"Issued To: {issued_to}")
    y -= 18
    c.drawCentredString(width/2, y, f"E-waste Type: {ewaste_type}")
    y -= 18
    if agent_name:
        c.drawCentredString(width/2, y, f"Collected By (Agent): {agent_name}")
        y -= 18
    if center_name:
        c.drawCentredString(width/2, y, f"Processed At (Center): {center_name}")
        y -= 18

    y -= 10
    c.drawCentredString(width/2, y, f"Issued On: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    y -= 30

    c.setFont("Helvetica-Oblique", 10)
    c.drawCentredString(width/2, 60, "This certifies responsible handover / recycling of collected e-waste.")
    c.showPage()
    c.save()

    return filename

def get_account_by_email(email):
    """
    Search admin -> agents -> centers -> users
    Return (row_dict, role_str) or (None, None)
    """
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM admin WHERE email=%s", (email,))
        row = cur.fetchone()
        if row:
            return row, "admin"

        cur.execute("SELECT * FROM agents WHERE email=%s", (email,))
        row = cur.fetchone()
        if row:
            return row, "agent"

        cur.execute("SELECT * FROM centers WHERE email=%s", (email,))
        row = cur.fetchone()
        if row:
            return row, "center"

        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        row = cur.fetchone()
        if row:
            return row, "user"
    finally:
        cur.close()
        conn.close()
    return None, None

# Role helpers
def require_admin(): return session.get("role") == "admin"
def require_agent(): return session.get("role") == "agent"
def require_center(): return session.get("role") == "center"
def require_user(): return session.get("role") == "user"

# ---------------------------
# Routes - auth & registration
# ---------------------------
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/register_user", methods=["GET", "POST"])
def register_user():
    if request.method == "POST":
        fullname = request.form.get("fullname")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        address = request.form.get("address")
        mobile = request.form.get("mobile")
        lat = request.form.get("latitude")
        lon = request.form.get("longitude")
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register_user"))
        pic = save_profile_pic(request.files.get("profilePic"))
        hashed = generate_password_hash(password)
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO users (fullname, email, password, mobile, address, latitude, longitude, profile_pic)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (fullname, email, hashed, mobile, address, lat, lon, pic))
            conn.commit()
            flash("Registered successfully. Please login.", "success")
            return redirect(url_for("login"))
        except mysql.connector.IntegrityError:
            flash("Email already exists.", "danger")
            return redirect(url_for("register_user"))
        finally:
            cur.close()
            conn.close()
    return render_template("register_user.html")

@app.route("/register_agent", methods=["GET", "POST"])
def register_agent():
    if request.method == "POST":
        fullname = request.form.get("fullname")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        address = request.form.get("address")
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register_agent"))
        pic = save_profile_pic(request.files.get("profilePic"))
        hashed = generate_password_hash(password)
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO agents (fullname, email, password, mobile, address, profile_pic, is_approved)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (fullname, email, hashed, mobile, address, pic, 0))
            conn.commit()
            flash("Agent registered. Await admin approval.", "success")
            return redirect(url_for("login"))
        except mysql.connector.IntegrityError:
            flash("Email already exists.", "danger")
            return redirect(url_for("register_agent"))
        finally:
            cur.close()
            conn.close()
    return render_template("register_agent.html")

@app.route("/register_center", methods=["GET", "POST"])
def register_center():
    if request.method == "POST":
        center_name = request.form.get("center_name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        address = request.form.get("address")
        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register_center"))
        pic = save_profile_pic(request.files.get("profilePic"))
        hashed = generate_password_hash(password)
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO centers (center_name, email, password, mobile, address, profile_pic, is_approved)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (center_name, email, hashed, mobile, address, pic, 0))
            conn.commit()
            flash("Center registered. Await admin approval.", "success")
            return redirect(url_for("login"))
        except mysql.connector.IntegrityError:
            flash("Email already exists.", "danger")
            return redirect(url_for("register_center"))
        finally:
            cur.close()
            conn.close()
    return render_template("register_center.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        email = request.form.get("username")
        password = request.form.get("password")
        row, role = get_account_by_email(email)
        if not row:
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))
        if not check_password_hash(row["password"], password):
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))
        # approval check for agent/center
        if role in ("agent", "center") and row.get("is_approved") == 0:
            flash("Account awaiting admin approval.", "warning")
            return redirect(url_for("login"))

        # set session
        session["user_id"] = row["id"]
        session["role"] = role
        session["profile_pic"] = row.get("profile_pic")
        if role == "admin":
            session["name"] = "Admin"
        elif role == "agent":
            session["name"] = row.get("fullname")
            # agent uses session["user_id"] as agent id
        elif role == "center":
            session["name"] = row.get("center_name")
            session["center_id"] = row["id"]
        else:  # user
            session["name"] = row.get("fullname")

        # redirect
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        if role == "agent":
            return redirect(url_for("agent_dashboard"))
        if role == "center":
            return redirect(url_for("center_dashboard"))
        return redirect(url_for("user_dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))

# ---------------------------
# User routes
# ---------------------------
@app.route("/user/dashboard")
def user_dashboard():
    if not require_user():
        flash("Please login as user.", "warning")
        return redirect(url_for("login"))
    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT pr.*, a.fullname AS agent_name, c.center_name
        FROM pickup_requests pr
        LEFT JOIN agents a ON pr.agent_id = a.id
        LEFT JOIN centers c ON pr.center_id = c.id
        WHERE pr.user_id = %s
        ORDER BY pr.requested_at DESC
    """, (user_id,))
    pickups = cur.fetchall()
    cur.close()
    conn.close()
    total = len(pickups)
    pending_count = sum(1 for p in pickups if p["status"] in ("pending","assigned","picked_up","handed_over","in_progress"))
    completed_count = sum(1 for p in pickups if p["status"] in ("recycled","completed"))
    return render_template("user_dashboard.html",
                           name=session.get("name"),
                           pickups=pickups,
                           total_pickups=total,
                           pending_count=pending_count,
                           completed_count=completed_count)

@app.route("/user/pickup/new", methods=["GET", "POST"])
def user_new_pickup():
    if not require_user():
        flash("Please login as user.", "warning")
        return redirect(url_for("login"))
    if request.method == "POST":
        user_id = session["user_id"]
        ewaste_type = request.form.get("ewaste_type")
        address = request.form.get("address")
        notes = request.form.get("notes")
        if not ewaste_type or not address:
            flash("Please fill required fields.", "danger")
            return redirect(url_for("user_new_pickup"))
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO pickup_requests (user_id, ewaste_type, address, notes, status)
            VALUES (%s,%s,%s,%s,'pending')
        """, (user_id, ewaste_type, address, notes))
        conn.commit()
        cur.close()
        conn.close()
        flash("Pickup requested successfully.", "success")
        return redirect(url_for("user_dashboard"))
    return render_template("user_new_pickup.html")

# ---------------------------
# Agent routes
# ---------------------------
@app.route("/agent/dashboard")
def agent_dashboard():
    if not require_agent():
        flash("Please login as agent.", "warning")
        return redirect(url_for("login"))
    agent_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT pr.*, u.fullname AS user_name, c.center_name
        FROM pickup_requests pr
        LEFT JOIN users u ON pr.user_id = u.id
        LEFT JOIN centers c ON pr.center_id = c.id
        WHERE pr.agent_id = %s
        ORDER BY pr.requested_at DESC
    """, (agent_id,))
    pickups = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("agent_dashboard.html",
                           pickups=pickups,
                           name=session.get("name"),
                           profile_pic=session.get("profile_pic"))

@app.route("/agent/pickup/<int:pickup_id>/status", methods=["POST"])
def agent_update_pickup_status(pickup_id):
    if not require_agent():
        flash("Please login as agent.", "warning")
        return redirect(url_for("login"))
    new_status = request.form.get("status")
    # agent allowed statuses: picked_up, handed_over (as per your confirmed flow)
    if new_status not in ("picked_up", "handed_over", "in_progress", "completed"):
        flash("Invalid status update by agent.", "danger")
        return redirect(url_for("agent_dashboard"))
    conn = get_db_connection()
    cur = conn.cursor()
    # ensure agent can only update their assigned pickups
    cur.execute("""
        UPDATE pickup_requests
        SET status = %s
        WHERE id = %s AND agent_id = %s
    """, (new_status, pickup_id, session["user_id"]))
    conn.commit()
    cur.close()
    conn.close()
    flash("Pickup status updated.", "success")
    return redirect(url_for("agent_dashboard"))

# ---------------------------
# Center routes
# ---------------------------
@app.route("/center/dashboard")
def center_dashboard():
    if not require_center():
        flash("Please login as center.", "warning")
        return redirect(url_for("login"))
    center_id = session["center_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT pr.*, u.fullname AS user_name, a.fullname AS agent_name
        FROM pickup_requests pr
        LEFT JOIN users u ON pr.user_id = u.id
        LEFT JOIN agents a ON pr.agent_id = a.id
        WHERE pr.center_id = %s
        ORDER BY pr.requested_at DESC
    """, (center_id,))
    pickups = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("center_dashboard.html",
                           name=session.get("name"),
                           pickups=pickups)

@app.route("/center/new-pickup")
def center_new_pickup():
    if not require_center():
        flash("Please login as center.", "warning")
        return redirect(url_for("login"))
    center_id = session["center_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT pr.*, u.fullname AS user_name, a.fullname AS agent_name
        FROM pickup_requests pr
        LEFT JOIN users u ON pr.user_id = u.id
        LEFT JOIN agents a ON pr.agent_id = a.id
        WHERE pr.center_id = %s AND pr.status IN ('assigned','picked_up','handed_over')
        ORDER BY pr.requested_at DESC
    """, (center_id,))
    requests = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("center_new_pickup.html", requests=requests)

@app.route("/center/received/<int:pickup_id>", methods=["POST"])
def center_received(pickup_id):
    """
    Mark as received (handover) and generate handover certificate (certificate_path).
    """
    if not require_center():
        flash("Please login as center.", "warning")
        return redirect(url_for("login"))
    center_id = session["center_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    # verify ownership
    cur.execute("SELECT * FROM pickup_requests WHERE id=%s AND center_id=%s", (pickup_id, center_id))
    pickup = cur.fetchone()
    if not pickup:
        cur.close()
        conn.close()
        flash("Pickup not found or not authorized.", "danger")
        return redirect(url_for("center_dashboard"))

    # fetch user/agent details
    user_id = pickup.get("user_id")
    agent_id = pickup.get("agent_id")
    ewaste_type = pickup.get("ewaste_type") or "N/A"

    cur.execute("SELECT fullname FROM users WHERE id=%s", (user_id,))
    u = cur.fetchone()
    user_name = u["fullname"] if u else "User"

    agent_name = None
    if agent_id:
        cur.execute("SELECT fullname FROM agents WHERE id=%s", (agent_id,))
        a = cur.fetchone()
        agent_name = a["fullname"] if a else None

    # generate handover certificate (certificate_path)
    cert_filename = generate_certificate_pdf(pickup_id, "handover", user_name, ewaste_type,
                                             center_name=session.get("name"), agent_name=agent_name)

    # update DB: status 'received' and certificate_path
    cur.execute("""
        UPDATE pickup_requests
        SET status=%s, certificate_path=%s
        WHERE id=%s
    """, ("received", cert_filename, pickup_id))
    conn.commit()

    cur.close()
    conn.close()
    flash("Pickup marked received and handover certificate generated.", "success")
    return redirect(url_for("center_dashboard"))

@app.route("/center/recycled/<int:pickup_id>", methods=["POST"])
def center_recycled(pickup_id):
    """
    Mark as recycled (final) and generate recycle certificate (certificate_pdf).
    """
    if not require_center():
        flash("Please login as center.", "warning")
        return redirect(url_for("login"))
    center_id = session["center_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    # verify
    cur.execute("SELECT * FROM pickup_requests WHERE id=%s AND center_id=%s", (pickup_id, center_id))
    pickup = cur.fetchone()
    if not pickup:
        cur.close()
        conn.close()
        flash("Pickup not found or not authorized.", "danger")
        return redirect(url_for("center_dashboard"))

    # prepare certificate data
    user_id = pickup.get("user_id")
    agent_id = pickup.get("agent_id")
    ewaste_type = pickup.get("ewaste_type") or "N/A"

    cur.execute("SELECT fullname FROM users WHERE id=%s", (user_id,))
    u = cur.fetchone()
    user_name = u["fullname"] if u else "User"

    agent_name = None
    if agent_id:
        cur.execute("SELECT fullname FROM agents WHERE id=%s", (agent_id,))
        a = cur.fetchone()
        agent_name = a["fullname"] if a else None

    # generate recycle certificate
    cert_filename = generate_certificate_pdf(pickup_id, "recycle", user_name, ewaste_type,
                                             center_name=session.get("name"), agent_name=agent_name)

    # update DB: status 'recycled' and certificate_pdf
    cur.execute("""
        UPDATE pickup_requests
        SET status=%s, certificate_pdf=%s
        WHERE id=%s
    """, ("recycled", cert_filename, pickup_id))
    conn.commit()

    cur.close()
    conn.close()
    flash("Pickup marked recycled and recycle-certificate generated.", "success")
    return redirect(url_for("center_dashboard"))

# ---------------------------
# Admin routes
# ---------------------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if not require_admin():
        flash("Please login as admin.", "warning")
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN status='assigned' THEN 1 ELSE 0 END) AS assigned,
            SUM(CASE WHEN status='picked_up' THEN 1 ELSE 0 END) AS picked_up,
            SUM(CASE WHEN status='handed_over' THEN 1 ELSE 0 END) AS handed_over,
            SUM(CASE WHEN status='received' THEN 1 ELSE 0 END) AS received,
            SUM(CASE WHEN status='recycled' THEN 1 ELSE 0 END) AS recycled
        FROM pickup_requests
    """)
    stats = cur.fetchone() or {}
    cur.execute("""
        SELECT pr.id, pr.status, pr.ewaste_type, u.fullname AS user_name,
               c.center_name, a.fullname AS agent_name
        FROM pickup_requests pr
        LEFT JOIN users u ON pr.user_id = u.id
        LEFT JOIN centers c ON pr.center_id = c.id
        LEFT JOIN agents a ON pr.agent_id = a.id
        ORDER BY pr.id DESC
        LIMIT 20
    """)
    recent = cur.fetchall()

    # lists for dropdowns
    try:
        cur.execute("SELECT id, fullname FROM agents WHERE is_approved=1")
    except Exception:
        cur.execute("SELECT id, fullname FROM agents")
    agents = cur.fetchall()
    try:
        cur.execute("SELECT id, center_name FROM centers WHERE is_approved=1")
    except Exception:
        cur.execute("SELECT id, center_name FROM centers")
    centers = cur.fetchall()

    cur.close()
    conn.close()
    return render_template("admin_dashboard.html",
                           stats=stats, requests=recent, agents=agents, centers=centers)

@app.route("/admin/requests")
def admin_requests():
    if not require_admin():
        flash("Please login as admin.", "warning")
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT pr.id, pr.status, pr.ewaste_type, pr.address, pr.notes,
               u.fullname as user_name, c.center_name, a.fullname as agent_name
        FROM pickup_requests pr
        LEFT JOIN users u ON pr.user_id = u.id
        LEFT JOIN centers c ON pr.center_id = c.id
        LEFT JOIN agents a ON pr.agent_id = a.id
        ORDER BY pr.id DESC
    """)
    requests_list = cur.fetchall()
    try:
        cur.execute("SELECT id, center_name FROM centers WHERE is_approved=1")
    except Exception:
        cur.execute("SELECT id, center_name FROM centers")
    centers = cur.fetchall()
    try:
        cur.execute("SELECT id, fullname FROM agents WHERE is_approved=1")
    except Exception:
        cur.execute("SELECT id, fullname FROM agents")
    agents = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("admin_requests.html", requests=requests_list, centers=centers, agents=agents)

@app.route("/admin/assign/<int:pickup_id>", methods=["POST"])
def admin_assign_pickup(pickup_id):
    if not require_admin():
        flash("Please login as admin.", "warning")
        return redirect(url_for("login"))
    agent_id = request.form.get("agent_id")
    center_id = request.form.get("center_id")  # optional
    if not agent_id:
        flash("Please choose an agent to assign.", "warning")
        return redirect(request.referrer or url_for("admin_requests"))
    conn = get_db_connection()
    cur = conn.cursor()
    if center_id:
        cur.execute("""
            UPDATE pickup_requests
            SET agent_id=%s, center_id=%s, status='assigned'
            WHERE id=%s
        """, (agent_id, center_id, pickup_id))
    else:
        cur.execute("""
            UPDATE pickup_requests
            SET agent_id=%s, status='assigned'
            WHERE id=%s
        """, (agent_id, pickup_id))
    conn.commit()
    cur.close()
    conn.close()
    flash("Pickup assigned successfully.", "success")
    return redirect(request.referrer or url_for("admin_requests"))

@app.route("/admin/agents")
def admin_agents():
    if not require_admin():
        flash("Please login as admin.", "warning")
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, fullname, email, mobile, is_approved FROM agents ORDER BY id DESC")
    except Exception:
        cur.execute("SELECT id, fullname, email, mobile FROM agents ORDER BY id DESC")
    agents = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("admin_agents.html", agents=agents)

@app.route("/admin/agents/<int:agent_id>/approve")
def admin_approve_agent(agent_id):
    if not require_admin():
        flash("Please login as admin.", "warning")
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE agents SET is_approved=1 WHERE id=%s", (agent_id,))
        conn.commit()
    except Exception:
        pass
    cur.close()
    conn.close()
    flash("Agent approved.", "success")
    return redirect(url_for("admin_agents"))

@app.route("/admin/centers")
def admin_centers():
    if not require_admin():
        flash("Please login as admin.", "warning")
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, center_name, email, is_approved FROM centers ORDER BY id DESC")
    except Exception:
        cur.execute("SELECT id, center_name, email FROM centers ORDER BY id DESC")
    centers = cur.fetchall()
    cur.close()
    conn.close()
    return render_template("admin_centers.html", centers=centers)

@app.route("/admin/centers/<int:center_id>/approve")
def admin_approve_center(center_id):
    if not require_admin():
        flash("Please login as admin.", "warning")
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE centers SET is_approved=1 WHERE id=%s", (center_id,))
        conn.commit()
    except Exception:
        pass
    cur.close()
    conn.close()
    flash("Center approved.", "success")
    return redirect(url_for("admin_centers"))

@app.route("/admin/pending")
def admin_pending():
    if not require_admin():
        flash("Please login as admin.", "warning")
        return redirect(url_for("login"))
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, center_name, address FROM centers WHERE is_approved=0 ORDER BY id DESC")
        pending_centers = cur.fetchall()
    except Exception:
        pending_centers = []
    try:
        cur.execute("SELECT id, fullname, email, mobile FROM agents WHERE is_approved=0 ORDER BY id DESC")
        pending_agents = cur.fetchall()
    except Exception:
        pending_agents = []
    cur.close()
    conn.close()
    return render_template("admin_pending.html", pending_centers=pending_centers, pending_agents=pending_agents)

# ---------------------------
# Certificate download
# ---------------------------
@app.route("/certificate/<path:filename>")
def download_certificate(filename):
    # shows inline in browser; change as_attachment=True to force download
    return send_from_directory(app.config["CERT_FOLDER"], filename, as_attachment=False)

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
