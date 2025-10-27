import os

from dotenv import load_dotenv
load_dotenv()
import socket
import qrcode
# CORRECTED: render_template, redirect, url_for are imported
from flask import Flask, jsonify, request, render_template_string, render_template, redirect, url_for, send_file
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from twilio.rest import Client # ✅ Twilio
from twilio.base.exceptions import TwilioRestException # 🚨 NEW IMPORT FOR TWILIO ERRORS
from extensions import db
from models import User, Patient, EmergencyContact, Report
from datetime import datetime, timezone, timedelta
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


# In-memory dictionary to track alert times


# ---------------- Setup ----------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# ✅ Persistent DB path (for Render disk)
db_path = "/opt/data/carecode.db" if os.path.exists("/opt/data") else "carecode.db"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Removed: MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER configurations

# Removed: mail = Mail(app) initialization

# folders for uploads
BASE_STATIC = os.path.join(os.path.dirname(__file__), "static")
QRC_DIR = os.path.join(BASE_STATIC, "qrcodes")
REPO_DIR = os.path.join(BASE_STATIC, "reports")
os.makedirs(QRC_DIR, exist_ok=True)
os.makedirs(REPO_DIR, exist_ok=True)

db.init_app(app)

# Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- Utils ----------------

# 🚨 CORRECTED FUNCTION: VALIDATE PHONE NUMBER (Removed duplicated logic)
def validate_phone_number(phone_string):
    """
    Uses Twilio Lookup to validate and standardize a phone number.
    Returns (is_valid: bool, standardized_phone: str or error_message: str)
    """
    try:
        # CORRECTED LINE: Removed invalid 'fields' parameter for v2 Lookup API fetch call.
        lookup = client.lookups.v2.phone_numbers(phone_string).fetch()

        # Check if Twilio returned a valid E.164 format
        if lookup.phone_number:
            return True, lookup.phone_number
        else:
            return False, "Invalid phone number format."

    except TwilioRestException as e:
        # Twilio throws a 404 error (code 20404) if the number is invalid
        if e.status == 404:
            return False, "Phone number is invalid or not a working number."
        else:
            # Handle other Twilio errors (e.g., authentication, network)
            print(f"Twilio Lookup Error: {e}")
            return False, "Validation service error. Try again later."
    except Exception as e:
        print(f"General Validation Error: {e}")
        return False, "An unexpected error occurred during validation."

def contact_dict(c):
    # Added ID to contact dict for deletion purposes
    return {"id": c.id, "name": c.name, "phone": c.phone, "relation": c.relation}

def report_dict(r):
    return {
        "id": r.id,
        "filename": r.filename,
        "description": r.description,
        "uploaded_at": r.uploaded_at.isoformat()
    }

def patient_public_dict(p):
    contacts = EmergencyContact.query.filter_by(patient_uuid=p.uuid).all()
    return {
        "uuid": p.uuid,
        "name": p.name,
        "age": p.age,
        "blood_group": p.blood_group,
        "allergies": p.allergies,
        "medications": p.medications,
        "emergency_contacts": [contact_dict(c) for c in contacts]
    }

def patient_staff_dict(p):
    data = patient_public_dict(p)
    reports = Report.query.filter_by(patient_uuid=p.uuid).order_by(Report.uploaded_at.desc()).all()
    data["reports"] = [report_dict(r) for r in reports]
    return data

# ---------------- Twilio SMS Sender ----------------
from twilio.rest import Client

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

twilio_client = None
if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


def send_sms(to_number, message):
    try:
        msg = client.messages.create(
            body=message,
            from_=TWILIO_PHONE,
            to=to_number
        )
        print(f"✅ SMS sent to {to_number}, SID={msg.sid}")
    except Exception as e:
        print(f"❌ SMS failed: {e}")

# ---------------- Routes ----------------

# ---------- AUTH ----------
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    if not data.get("email") or not data.get("password"):
        return {"error":"email and password required"}, 400
    if User.query.filter_by(email=data["email"]).first():
        return {"error":"email already exists"}, 400

    u = User(email=data["email"], role=data.get("role","patient"))
    u.set_password(data["password"])
    db.session.add(u); db.session.commit()

    if u.role == "patient":
        p = Patient(
            user_id=u.id,
            name=data.get("name",""),
            age=int(data.get("age",0)),
            blood_group=data.get("blood_group","Unknown")
        )
        db.session.add(p); db.session.commit()

    return {"message":"user created", "role": u.role}, 201

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    user = User.query.filter_by(email=data.get("email")).first()
    if user and user.check_password(data.get("password","")):
        login_user(user)
        # Modified to return a redirect URL for the frontend JavaScript
        if user.role == 'patient':
            return jsonify({"redirect": url_for('patient_dashboard')})
        elif user.role == 'staff':
            return jsonify({"redirect": url_for('staff_dashboard')})
    return {"error":"invalid credentials"}, 401

# Removed: @app.route("/auth/forgot_password", methods=["POST"])
# Removed: @app.route("/auth/reset_password_page/<int:user_id>", methods=["GET", "POST"])

@app.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    # Modified to return a redirect URL for the frontend JavaScript
    return jsonify({"message":"logged out", "redirect": url_for('index')})

# ---------- PATIENT (self) ----------
@app.route("/me", methods=["GET"])
@login_required
def my_profile():
    if current_user.role != "patient":
        return {"error":"only patients allowed"}, 403
    return patient_staff_dict(current_user.patient)

@app.route("/me", methods=["PUT"])
@login_required
def update_my_profile():
    if current_user.role != "patient":
        return {"error":"only patients allowed"}, 403
    data = request.get_json() or {}
    p = current_user.patient
    for f in ["name","age","blood_group","allergies","medications"]:
        if f in data: setattr(p, f, data[f])
    db.session.commit()
    return {"message":"updated", "patient": patient_staff_dict(p)}

@app.route("/me/reports", methods=["POST"])
@login_required
def upload_my_report():
    if current_user.role != "patient":
        return {"error":"only patients allowed"}, 403
    p = current_user.patient
    if "file" not in request.files:
        return {"error":"no file"}, 400
    f = request.files["file"]
    safe = secure_filename(f.filename)
    patient_dir = os.path.join(REPO_DIR, p.uuid)
    os.makedirs(patient_dir, exist_ok=True)
    path = os.path.join(patient_dir, safe)
    f.save(path)
    rel_path = os.path.join("static","reports",p.uuid,safe).replace("\\","/")
    r = Report(patient_uuid=p.uuid, filename=rel_path, description=request.form.get("description",""))
    db.session.add(r); db.session.commit()
    return {"message":"uploaded", "report": report_dict(r)}

## NEW FEATURE: Download Patient Report
@app.route("/me/reports/<int:report_id>/download", methods=["GET"])
@login_required
def download_my_report(report_id):
    if current_user.role != "patient":
        return {"error":"only patients allowed"}, 403
    
    report = Report.query.filter_by(id=report_id, patient_uuid=current_user.patient.uuid).first()
    if not report:
        return {"error": "Report not found"}, 404

    # The filename path is relative to the static folder, we need the absolute path
    # The filename in DB is stored as: 'static/reports/<uuid>/<filename>'
    file_path = os.path.join(app.root_path, report.filename) 
    
    if not os.path.exists(file_path):
        return {"error": "File not found on server"}, 404

    return send_file(file_path, as_attachment=True, download_name=os.path.basename(file_path))

## NEW FEATURE: Delete Patient Report
@app.route("/me/reports/<int:report_id>", methods=["DELETE"])
@login_required
def delete_my_report(report_id):
    if current_user.role != "patient":
        return {"error":"only patients allowed"}, 403

    report = Report.query.filter_by(id=report_id, patient_uuid=current_user.patient.uuid).first()
    if not report:
        return {"error": "Report not found"}, 404

    # 1. Delete the file from the filesystem
    file_path = os.path.join(app.root_path, report.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    # 2. Delete the record from the database
    db.session.delete(report)
    db.session.commit()
    
    return {"message": f"Report {report_id} deleted successfully"}, 200

@app.route("/me/reports", methods=["GET"])
@login_required
def list_my_reports():
    if current_user.role != "patient":
        return {"error":"only patients allowed"}, 403
    p = current_user.patient
    reps = Report.query.filter_by(patient_uuid=p.uuid).all()
    return {"reports": [report_dict(r) for r in reps]}

# ---------- PATIENT EMERGENCY CONTACTS ----------
# In app.py
# ---------- PATIENT EMERGENCY CONTACTS ----------
@app.route("/me/contacts", methods=["POST"])
@login_required
def add_contact():
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403

    data = request.get_json() or {}
    if not data.get("name") or not data.get("phone"):
        return {"error": "name and phone required"}, 400

    # 🚨 STEP 1: VALIDATE NUMBER VIA TWILIO LOOKUP
    is_valid, standardized_phone = validate_phone_number(data["phone"])

    if not is_valid:
        return {"error": standardized_phone}, 400 # Return the error message

    # 🚨 STEP 2: Use the standardized number if validation passed
    c = EmergencyContact(
        patient_uuid=current_user.patient.uuid,
        name=data["name"],
        phone=standardized_phone, # Use the standardized E.164 number
        relation=data.get("relation", "")
    )
    db.session.add(c)
    db.session.commit()
    return {"message": "contact added", "contact": contact_dict(c)}

## NEW FEATURE: Delete Emergency Contact
@app.route("/me/contacts/<int:contact_id>", methods=["DELETE"])
@login_required
def delete_contact(contact_id):
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403

    # Ensure the contact belongs to the current patient
    contact = EmergencyContact.query.filter_by(
        id=contact_id, 
        patient_uuid=current_user.patient.uuid
    ).first()

    if not contact:
        return {"error": "Contact not found or does not belong to patient"}, 404

    db.session.delete(contact)
    db.session.commit()
    
    return {"message": f"Contact {contact_id} deleted successfully"}, 200
# ------------------ TWILIO VERIFY SETUP ------------------
# ⚠️ Create a Verify Service in Twilio Console and paste its SID below
TWILIO_VERIFY_SID = os.getenv("TWILIO_VERIFY_SID")  # from Render env vars


# ------------------ NEW: Send OTP to Contact ------------------
@app.route("/me/contacts/send_otp", methods=["POST"])
@login_required
def send_contact_otp():
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403

    data = request.get_json() or {}
    name = data.get("name")
    phone = data.get("phone")
    relation = data.get("relation", "")

    if not name or not phone:
        return {"error": "name and phone required"}, 400

    # Validate format
    is_valid, standardized_phone = validate_phone_number(phone)
    if not is_valid:
        return {"error": standardized_phone}, 400

    try:
        # Send OTP via Twilio Verify
        verification = client.verify.v2.services(TWILIO_VERIFY_SID).verifications.create(
            to=standardized_phone,
            channel="sms"
        )
        return {"message": f"OTP sent to {standardized_phone}", "phone": standardized_phone}, 200
    except Exception as e:
        print(f"OTP send failed: {e}")
        return {"error": "Failed to send OTP. Please try again."}, 500


# ------------------ NEW: Verify OTP and Save Contact ------------------
@app.route("/me/contacts/verify_otp", methods=["POST"])
@login_required
def verify_contact_otp():
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403

    data = request.get_json() or {}
    name = data.get("name")
    relation = data.get("relation", "")
    phone = data.get("phone")
    otp = data.get("otp")

    if not (name and phone and otp):
        return {"error": "name, phone, and otp required"}, 400

    try:
        verification_check = client.verify.v2.services(TWILIO_VERIFY_SID).verification_checks.create(
            to=phone,
            code=otp
        )

        if verification_check.status == "approved":
            # Save the verified contact
            c = EmergencyContact(
                patient_uuid=current_user.patient.uuid,
                name=name,
                phone=phone,
                relation=relation
            )
            db.session.add(c)
            db.session.commit()
            return {"message": "Contact verified and added successfully", "contact": contact_dict(c)}, 201
        else:
            return {"error": "Invalid OTP"}, 400

    except Exception as e:
        print(f"OTP verification failed: {e}")
        return {"error": "Verification failed. Try again later."}, 500


# ---------- STAFF ----------
@app.route("/staff/patients", methods=["GET"])
@login_required
def list_all_patients():
    if current_user.role != "staff":
        return {"error": "only staff allowed"}, 403
    patients = Patient.query.all()
    return {"patients": [patient_staff_dict(p) for p in patients]}

@app.route("/staff/patient/<string:uuid>", methods=["GET"])
@login_required
def staff_view(uuid):
    if current_user.role != "staff":
        return {"error":"only staff allowed"}, 403
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p: return {"error":"not found"}, 404
    return patient_staff_dict(p)

@app.route("/staff/patient/<string:uuid>/reports", methods=["POST"])
@login_required
def staff_upload_report(uuid):
    if current_user.role != "staff":
        return {"error":"only staff allowed"}, 403
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p: return {"error":"not found"}, 404
    if "file" not in request.files:
        return {"error":"no file"}, 400
    f = request.files["file"]
    safe = secure_filename(f.filename)
    patient_dir = os.path.join(REPO_DIR, uuid)
    os.makedirs(patient_dir, exist_ok=True)
    path = os.path.join(patient_dir, safe)
    f.save(path)
    rel_path = os.path.join("static","reports",uuid,safe).replace("\\","/")
    r = Report(patient_uuid=uuid, filename=rel_path, description=request.form.get("description",""))
    db.session.add(r); db.session.commit()
    return {"message":"uploaded", "report": report_dict(r)}

@app.route("/staff/search", methods=["GET"])
@login_required
def staff_search():
    if current_user.role != "staff":
        return {"error": "only staff allowed"}, 403

    name = request.args.get("name")
    email = request.args.get("email")

    query = Patient.query
    if name:
        query = query.filter(Patient.name.ilike(f"%{name}%"))
    if email:
        query = query.join(User).filter(User.email.ilike(f"%{email}%"))

    results = query.all()
    if not results:
        return {"error": "no matching patients found"}, 404

    return {"patients": [patient_staff_dict(p) for p in results]}

# ---------- PUBLIC ----------
# ✅ Prevent duplicate alerts within 2 hours
last_alert_time = {}
# app.py - Corrected /patient/<string:uuid> route

@app.route("/patient/<string:uuid>", methods=["GET"])
def public_patient(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error": "not found"}, 404

    contacts = EmergencyContact.query.filter_by(patient_uuid=p.uuid).all()
    contact_html = "".join(
        [f"<li>{c.name} ({c.relation}) - {c.phone}</li>" for c in contacts]
    )

    # Note: The HTML must be a single string for render_template_string
    html = f"""
    <html>
    <head>
        <title>Patient Info - {p.name}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f9f9f9;
                color: #333;
            }}
            .card {{
                max-width: 520px;
                margin: auto;
                background: white;
                padding: 20px;
                border-radius: 12px;
                box-shadow: 0px 0px 10px rgba(0,0,0,0.1);
            }}
            h2 {{ color: #2c3e50; text-align: center; }}
            p {{ margin: 5px 0; }}
            ul {{ padding-left: 20px; }}
            .alert-text {{ 
                text-align:center;
                color:#c0392b; 
                font-weight:bold;
                margin-top:15px; 
                border-top: 1px solid #eee;
                padding-top: 10px;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>🚨 Emergency Alert: {p.name}</h2>
            <p><strong>Age:</strong> {p.age}</p>
            <p><strong>Blood Group:</strong> {p.blood_group}</p>
            <p><strong>Allergies:</strong> {p.allergies or "None"}</p>
            <p><strong>Medications:</strong> {p.medications or "None"}</p>
            <h3>Emergency Contacts:</h3>
            <ul>{contact_html or "<li>No emergency contacts available</li>"}</ul>
            <p class="alert-text">
                📍 Attempting to send alert SMS to contacts...
            </p>
        </div>

        <script>
const uuid = "{uuid}";
console.log("QR page opened for:", uuid);

// Check if Geolocation is supported
if (navigator.geolocation) {{
    // This call triggers the 'Allow Location' pop-up
    navigator.geolocation.getCurrentPosition(
        // Success: Location access granted
        (pos) => {{
            console.log("✅ Location access granted");
            fetch(`/report_location/${{uuid}}`, {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                // Send lat/lon in the request body
                body: JSON.stringify({{
                    latitude: pos.coords.latitude,
                    longitude: pos.coords.longitude
                }})
            }})
            .then(r => console.log("✅ Alert sent WITH location", r.status));
            document.querySelector('.alert-text').textContent = '✅ Emergency alert sent with your current location!';
        }},
        // Error: Location access denied or failed
        (err) => {{
            console.warn("⚠️ Location denied or failed:", err);
            // Send alert WITHOUT location data
            fetch(`/report_location/${{uuid}}`, {{
                method: 'POST',
                // No body needed for the locationless alert
            }})
            .then(r => console.log("✅ Alert sent WITHOUT location", r.status));
            document.querySelector('.alert-text').textContent = '⚠️ Location denied. Emergency alert sent without live location.';
        }}
    );
}} else {{
    console.log("Geolocation not supported by this browser.");
    document.querySelector('.alert-text').textContent = '⚠️ Geolocation not supported. Alert sent without live location.';
    // Fallback: Send alert even if geolocation is not supported
    fetch(`/report_location/${{uuid}}`, {{ method: 'POST' }})
        .then(r => console.log("✅ Alert sent (geolocation not supported)", r.status));
}}
        </script>
    </body>
    </html>
    """
    return render_template_string(html)


from datetime import datetime, timezone, timedelta

@app.route("/report_location/<string:uuid>", methods=["POST"])
def report_location(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error": "patient not found"}, 404

    # ✅ Always use Indian time (no tzdata needed)
    now_ist = datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
    scan_time = now_ist.strftime("%Y-%m-%d %I:%M:%S %p IST")

    # ✅ Get location (if available)
    data = request.get_json(silent=True) or {}
    lat, lon = data.get("latitude"), data.get("longitude")

    if lat and lon:
        location_link = f"https://www.google.com/maps?q={lat},{lon}"
        alert_msg = (
            f"🚨 QR for {p.name} scanned at {scan_time}\n"
            f"📍 Live Location: {location_link}"
        )
    else:
        alert_msg = f"🚨 QR for {p.name} scanned at {scan_time}\n📍 Location not shared."

    # ✅ Send SMS to all emergency contacts every scan (no limit)
    contacts = EmergencyContact.query.filter_by(patient_uuid=p.uuid).all()
    if not contacts:
        print("⚠️ No emergency contacts found for this patient.")
    for c in contacts:
        send_sms(c.phone, alert_msg)

    print(f"✅ Alert sent for {p.name} at {scan_time}")
    return {"status": "ok", "message": "Alert sent successfully"}



@app.route("/generate_qr/<string:uuid>", methods=["GET"])
def generate_qr(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error":"not found"}, 404

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    qr_url = f"{BASE_URL}/patient/{uuid}"





    out = os.path.join(QRC_DIR, f"{uuid}.png")
    qrcode.make(url).save(out)

    rel = os.path.join("static","qrcodes", f"{uuid}.png").replace("\\","/")
    return {"qr": rel, "opens": url}

## NEW FEATURE: Download QR Code Image
@app.route("/generate_qr/<string:uuid>/download", methods=["GET"])
def download_qr(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error":"not found"}, 404

    file_path = os.path.join(QRC_DIR, f"{uuid}.png")
    if not os.path.exists(file_path):
        # Regenerate if not found
        result = generate_qr(uuid)
        if "error" in result:
             return result, 404
        # Wait for the file to be saved, then proceed
        
    return send_file(file_path, as_attachment=True, download_name=f"carecode_qr_{uuid}.png")


# ---------------- NEW FRONTEND ROUTES ----------------

@app.route("/")
def index():
    # Renders the main index page (index.html)
    return render_template("index.html")

@app.route("/patient/dashboard")
@login_required
def patient_dashboard():
    if current_user.role != "patient":
        return redirect(url_for('staff_dashboard')) # Redirect if logged in as staff
    # NOTE: Using your file name 'patient.html'
    return render_template("patient.html") 

@app.route("/staff/dashboard")
@login_required
def staff_dashboard():
    if current_user.role != "staff":
        return redirect(url_for('patient_dashboard')) # Redirect if logged in as patient
    # NOTE: Using your file name 'staff.html'
    return render_template("staff.html")

# ---------------- Init ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000)