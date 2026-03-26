import os
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

from zoneinfo import ZoneInfo
from models import User, Patient, EmergencyContact, Report, Hospital
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import sendgrid
from sendgrid.helpers.mail import Mail
from flask import Flask, request, jsonify
from ai_hospital import get_nearby_hospitals





# In-memory dictionary to track alert times


# ---------------- Setup ----------------
app = Flask(__name__)  # fixed

CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///carecode.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "fallback_secret")

serializer = URLSafeTimedSerializer(app.secret_key)

# Removed: MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USERNAME, MAIL_PASSWORD, MAIL_DEFAULT_SENDER configurations

# Removed: mail = Mail(app) initialization

# folders for uploads
BASE_STATIC = os.path.join(os.path.dirname(__file__), "static")  # fixed
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
        if not client:
           return False, "Validation service unavailable"
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
        "phone": p.phone,          # ✅ ADD THIS
        "photo": p.photo, 
        "emergency_contacts": [contact_dict(c) for c in contacts]
    }

def patient_staff_dict(p):
    data = patient_public_dict(p)
    reports = Report.query.filter_by(patient_uuid=p.uuid).order_by(Report.uploaded_at.desc()).all()
    data["reports"] = [report_dict(r) for r in reports]
    return data

# ---------------- Twilio SMS Sender ----------------
TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_AUTH = os.getenv("TWILIO_AUTH")
TWILIO_PHONE = os.getenv("TWILIO_PHONE")
# your Twilio trial number (still used as from_)

if TWILIO_SID and TWILIO_AUTH:
    client = Client(TWILIO_SID, TWILIO_AUTH)
else:
    client = None


def send_sms(to_number, message):
    if not client:
        print("Twilio not configured")
        return

    try:
        msg = client.messages.create(
            body=message,
            from_=TWILIO_PHONE,
            to=to_number
        )
        print(f"✅ SMS sent to {to_number}, SID={msg.sid}")
    except Exception as e:
        print(f"❌ SMS failed: {e}")


def make_call(to_number, patient_name):
    if not client:
        print("Twilio not configured")
        return

    try:
        call = client.calls.create(
            twiml=f"""
                <Response>
                    <Say voice="alice">
                        Emergency alert for {patient_name}.
                        Please check your phone immediately.
                    </Say>
                </Response>
            """,
            to=to_number,
            from_=TWILIO_PHONE
        )
        print(f"📞 Calling {to_number}")
    except Exception as e:
        print(f"❌ Call failed: {e}")

# ---------------- Routes ----------------

# ---------- AUTH ----------
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    # ✅ Basic validation
    if not data.get("email") or not data.get("password"):
        return {"error": "email and password required"}, 400
    if User.query.filter_by(email=data["email"]).first():
        return {"error": "email already exists"}, 400

    role = data.get("role", "patient")

    # ✅ STAFF REGISTRATION: Verify hospital code and restrict duplicates
    if role == "staff":
        code = data.get("hospital_code")
        if not code:
            return {"error": "Hospital code required for staff registration"}, 400

        hospital = Hospital.query.filter_by(code=code, verified=True).first()
        if not hospital:
            return {"error": "Invalid or unverified hospital code"}, 400

        # 🚫 Restrict: Allow only one staff per hospital
        existing_staff = User.query.filter_by(hospital_id=hospital.id).first()
        if existing_staff:
            return {"error": f"{hospital.name} already has a registered staff account."}, 400

        # ✅ Create new staff account linked to hospital
        u = User(email=data["email"], role="staff")
        u.set_password(data["password"])
        u.hospital_id = hospital.id
        db.session.add(u)
        db.session.commit()

        return {"message": f"Staff account created for {hospital.name}!"}, 201

    # ✅ PATIENT REGISTRATION (unchanged)
    u = User(email=data["email"], role="patient")
    u.set_password(data["password"])
    db.session.add(u)
    db.session.commit()

    p = Patient(
        user_id=u.id,
        name=data.get("name", ""),
        age=int(data.get("age", 0)),
        blood_group=data.get("blood_group", "Unknown")
    )
    db.session.add(p)
    db.session.commit()

    return {"message": "user created", "role": u.role}, 201

# ---------------- FORGOT PASSWORD ----------------
@app.route("/auth/forgot_password", methods=["POST"])
def forgot_password():
    data = request.get_json() or {}
    email = data.get("email")

    if not email:
        return {"error": "Email is required"}, 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return {"error": "No account found with this email"}, 404

    # Generate password reset token (valid for 10 minutes)
    token = serializer.dumps(email, salt="password-reset-salt")
    reset_link = f"{request.host_url}auth/reset_password/{token}"

    # Send email using SendGrid
    try:
        sg = sendgrid.SendGridAPIClient(api_key=os.getenv("SENDGRID_API_KEY"))
  # Replace this
        from_email = os.getenv("SENDGRID_FROM_EMAIL")
  # Must match verified sender
        subject = "Password Reset - CareCode"
        content = f"""
        <p>Hello,</p>
        
        <p>You requested to reset your password for CareCode.</p>
        <p>Click below to reset your password (valid for 10 minutes):</p>
        <p><a href="{reset_link}">{reset_link}</a></p>
        <p>If you didn’t request this, you can ignore this email.</p>
        <br>
        <p>— CareCode Support</p>
        """

        mail = Mail(from_email=from_email, to_emails=email, subject=subject, html_content=content)
        response = sg.send(mail)
        print(f"✅ Reset email sent to {email} (status {response.status_code})")

        return {"message": f"Password reset link sent to {email}"}, 200

    except Exception as e:
        print(f"❌ SendGrid Error: {e}")
        return {"error": "Failed to send email. Please try again."}, 500
    from itsdangerous import SignatureExpired, BadSignature


@app.route("/auth/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        # Decode token (valid for 10 minutes)
        email = serializer.loads(token, salt="password-reset-salt", max_age=600)
    except SignatureExpired:
        return "❌ The reset link has expired. Please request a new one.", 400
    except BadSignature:
        return "❌ Invalid or broken reset link.", 400

    if request.method == "POST":
        new_password = request.form.get("password")
        if not new_password:
            return "⚠️ Please enter a new password.", 400

        user = User.query.filter_by(email=email).first()
        if not user:
            return "User not found.", 404

        # ✅ Hash password properly before saving
        user.set_password(new_password)

        db.session.commit()

        return "✅ Password reset successful! You can now log in with your new password."

    # Show reset form (GET request)
    return render_template_string(f"""
        <h2>Reset Password for {email}</h2>
        <form method="POST">
            <input type="password" name="password" id="password" placeholder="Enter new password" required>
            <button type="button" onclick="togglePassword()">👁️</button>
            <br><br>
            <button type="submit">Reset Password</button>
        </form>
        <script>
        function togglePassword() {{
            var field = document.getElementById("password");
            field.type = field.type === "password" ? "text" : "password";
        }}
        </script>
    """)


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
# ⚠ Create a Verify Service in Twilio Console and paste its SID below
TWILIO_VERIFY_SID = os.getenv("TWILIO_VERIFY_SID")


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



@app.route("/staff/search", methods=["GET"])
@login_required
def staff_search():
    if current_user.role != "staff":
        return {"error": "only staff allowed"}, 403

    name = request.args.get("name")
    email = request.args.get("email")
    phone = request.args.get("phone")


    query = Patient.query
    if name:
        query = query.filter(Patient.name.ilike(f"%{name}%"))
    if email:
        query = query.join(User).filter(User.email.ilike(f"%{email}%"))
    if phone:
        query = query.filter(Patient.phone.like(f"%{phone}%"))


    results = query.all()
    if not results:
        return {"error": "no matching patients found"}, 404

    return {"patients": [patient_staff_dict(p) for p in results]}

# ---------- PUBLIC ----------
@app.route("/qr/<string:uuid>")
def qr_page(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error": "patient not found"}, 404

    contacts = EmergencyContact.query.filter_by(
        patient_uuid=p.uuid
    ).all()

    return render_template(
        "qr_page.html",
        p=p,
        contacts=contacts
    )

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
        <title>Scan2Save - {p.name}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f9f9f9;
                color: #333;
                margin: 20px;
            }}
            .card {{
                max-width: 520px;
                margin: auto;
                background: white;
                padding: 20px;
                border-radius: 12px;
                box-shadow: 0px 0px 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                text-align: center;
                color: #1a5276;
                margin-bottom: 5px;
            }}
            h3 {{
                text-align: center;
                font-weight: normal;
                color: #616161;
                margin-top: 0;
                margin-bottom: 15px;
            }}
            label {{
                display: block;
                margin-top: 15px;
                font-weight: bold;
            }}
            input {{
                width: 100%;
                padding: 10px;
                margin-top: 5px;
                border: 1px solid #ccc;
                border-radius: 6px;
            }}
            button {{
                width: 100%;
                padding: 10px;
                background-color: #c0392b;
                color: white;
                border: none;
                border-radius: 6px;
                margin-top: 15px;
                font-size: 16px;
                cursor: pointer;
            }}
            button:hover {{ background-color: #a93226; }}
            .status {{
                text-align: center;
                margin-top: 10px;
                font-weight: bold;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Scan2Save</h1>
            <h3>In case of emergencies, scan this QR for more details</h3>
            <h2>👤 {p.name}</h2>
            <p><strong>Age:</strong> {p.age}</p>
            <p><strong>Blood Group:</strong> {p.blood_group}</p>
            <p><strong>Phone:</strong> {p.phone if p.phone_verified else "Not verified"}</p>
            <p><strong>Allergies:</strong> {p.allergies or "None"}</p>
            <p><strong>Medications:</strong> {p.medications or "None"}</p>
            <h3>Emergency Contacts:</h3>
            <ul>{contact_html or "<li>No emergency contacts available</li>"}</ul>

            <label for="scanner_number">Your Phone Number (optional):</label>
            <input type="text" id="scanner_number" placeholder="Enter your phone number for updates">

            <button onclick="sendAlert()">🚨 Send Emergency Alert</button>
            <div class="status" id="status_msg"></div>
        </div>

        <script>
        const uuid = "{uuid}";

        function sendAlert() {{
            const number = document.getElementById('scanner_number').value;
            const status = document.getElementById('status_msg');

            status.textContent = "Requesting location permission...";

            if (navigator.geolocation) {{
                navigator.geolocation.getCurrentPosition(
                    (pos) => {{
                        const data = {{
                            latitude: pos.coords.latitude,
                            longitude: pos.coords.longitude,
                            scanner_number: number
                        }};
                        fetch(`/report_location/${{uuid}}`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify(data)
                        }})
                        .then(response => response.json())
                        .then(result => {{
                            if (result && result.status === 'ok') {{
                                status.textContent = "✅ Alert sent successfully with location.";
                            }} else {{
                                status.textContent = "⚠ Error sending alert.";
                            }}
                        }})
                        .catch(err => {{
                            console.error(err);
                            status.textContent = "⚠ Network or server error.";
                        }});
                    }},
                    (err) => {{
                        // user denied location or error
                        const data = {{ scanner_number: number }};
                        fetch(`/report_location/${{uuid}}`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify(data)
                        }})
                        .then(response => response.json())
                        .then(result => {{
                            if (result && result.status === 'ok') {{
                                status.textContent = "⚠ Alert sent without location (permission denied).";
                            }} else {{
                                status.textContent = "⚠ Error sending alert.";
                            }}
                        }})
                        .catch(err => {{
                            console.error(err);
                            status.textContent = "⚠ Network or server error.";
                        }});
                    }}
                );
            }} else {{
                // geolocation not supported
                const data = {{ scanner_number: number }};
                fetch(`/report_location/${{uuid}}`, {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify(data)
                }})
                .then(response => response.json())
                .then(result => {{
                    if (result && result.status === 'ok') {{
                        status.textContent = "⚠ Geolocation not supported. Alert sent without location.";
                    }} else {{
                        status.textContent = "⚠ Error sending alert.";
                    }}
                }})
                .catch(err => {{
                    console.error(err);
                    status.textContent = "⚠ Network or server error.";
                }});
            }}
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

    # ✅ Get location (if available) and scanner number (optional)
    data = request.get_json(silent=True) or {}
    lat, lon = data.get("latitude"), data.get("longitude")
    scanner_number = (data.get("scanner_number") or "").strip()

    # ✅ Clean, emoji-formatted message
    alert_msg = f"🚨 {p.name} alert!\n🕒 {scan_time}\n"

    if lat and lon:
        alert_msg += f"📍 https://maps.google.com/?q={lat},{lon}\n"
    else:
        alert_msg += "📍 Location not shared\n"

    if scanner_number:
        alert_msg += f"📞 {scanner_number}\n"

    alert_msg += "Call scanner for help."





    # ✅ Send SMS to all emergency contacts (include scanner’s number)
    contacts = EmergencyContact.query.filter_by(patient_uuid=p.uuid).all()
    if not contacts:
        print("⚠ No emergency contacts found for this patient.")
    else:
        for c in contacts:
            send_sms(c.phone, alert_msg)
            make_call(c.phone, p.name)

    print(f"✅ Alert sent for {p.name} at {scan_time}")
    return {"status": "ok", "message": "Alert sent successfully"}


@app.route("/generate_qr/<string:uuid>", methods=["GET"])
def generate_qr(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error": "not found"}, 404

    # ✅ Correct QR target
    base_url = request.host_url.rstrip("/")

    url = f"{base_url}/qr/{uuid}"                                

    out = os.path.join(QRC_DIR, f"{uuid}.png")
    qrcode.make(url).save(out)

    rel = os.path.join("static", "qrcodes", f"{uuid}.png").replace("\\", "/")
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
# ---------------- FORGOT PASSWORD ----------------
PHOTO_DIR = os.path.join(BASE_STATIC, "patient_photos")
os.makedirs(PHOTO_DIR, exist_ok=True)

@app.route("/me/phone/send_otp", methods=["POST"])
@login_required
def send_patient_phone_otp():
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403

    data = request.get_json() or {}
    phone = data.get("phone")
    if not phone:
        return {"error": "phone required"}, 400

    # one phone = one account
    if Patient.query.filter(
        Patient.phone == phone,
        Patient.id != current_user.patient.id
    ).first():
        return {"error": "Phone already registered"}, 400

    ok, standardized = validate_phone_number(phone)
    if not ok:
        return {"error": standardized}, 400

    client.verify.v2.services(TWILIO_VERIFY_SID).verifications.create(
        to=standardized,
        channel="sms"
    )

    p = current_user.patient
    p.phone = standardized
    p.phone_verified = False
    db.session.commit()

    return {"message": "OTP sent"}

@app.route("/me/phone/verify_otp", methods=["POST"])
@login_required
def verify_patient_phone_otp():
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403

    data = request.get_json() or {}
    otp = data.get("otp")
    p = current_user.patient

    if not otp or not p.phone:
        return {"error": "OTP required"}, 400

    check = client.verify.v2.services(TWILIO_VERIFY_SID).verification_checks.create(
        to=p.phone,
        code=otp
    )

    if check.status == "approved":
        p.phone_verified = True
        db.session.commit()
        return {"message": "Phone verified"}

    return {"error": "Invalid OTP"}, 400

@app.route("/me/upload_photo", methods=["POST"])
@login_required
def upload_photo():
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403

    if "photo" not in request.files:
        return {"error": "No file uploaded"}, 400

    file = request.files["photo"]

    if file.filename == "":
        return {"error": "No selected file"}, 400

    filename = secure_filename(file.filename)

    # Save file
    file_path = os.path.join(PHOTO_DIR, filename)
    file.save(file_path)

    # Save filename in DB
    p = current_user.patient
    p.photo = filename
    db.session.commit()

    return {"message": "Photo uploaded successfully", "filename": filename}

@app.route("/ai/hospitals")
def ai_hospitals():
    lat = request.args.get("lat")
    lon = request.args.get("lon")

    if not lat or not lon:
        return {"error": "Location required"}, 400

    hospitals = get_nearby_hospitals(lat, lon)

    return jsonify(hospitals)





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

    # ==================================================
# 🚀 QUICK ADD: PATIENT PHONE + PHOTO FEATURES
# ==================================================





# ==================================================
# STEP 5: PATIENT PHONE OTP VERIFICATION
# ==================================================

# Ensure photo folder exists (used in step 6 also)



# ---------------- Init ----------------
if __name__ == "__main__":  # fixed
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=False)
