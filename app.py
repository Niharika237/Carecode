import os
import socket
import qrcode
from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from twilio.rest import Client   # ✅ Twilio
from extensions import db
from models import User, Patient, EmergencyContact, Report

# ---------------- Setup ----------------
app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///carecode.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

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
def contact_dict(c):
    return {"name": c.name, "phone": c.phone, "relation": c.relation}

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


TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = "+12298003359"   # your Twilio trial number
client = Client(TWILIO_SID, TWILIO_AUTH)

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
@app.route("/")
def home():
    return jsonify({"message": "CareCode Backend Running"})

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
        return {"message":"logged in", "role": user.role}
    return {"error":"invalid credentials"}, 401

@app.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return {"message":"logged out"}

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

@app.route("/me/reports", methods=["GET"])
@login_required
def list_my_reports():
    if current_user.role != "patient":
        return {"error":"only patients allowed"}, 403
    p = current_user.patient
    reps = Report.query.filter_by(patient_uuid=p.uuid).all()
    return {"reports": [report_dict(r) for r in reps]}

# ---------- PATIENT EMERGENCY CONTACTS ----------
@app.route("/me/contacts", methods=["POST"])
@login_required
def add_contact():
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403

    data = request.get_json() or {}
    if not data.get("name") or not data.get("phone"):
        return {"error": "name and phone required"}, 400

    c = EmergencyContact(
        patient_uuid=current_user.patient.uuid,
        name=data["name"],
        phone=data["phone"],
        relation=data.get("relation", "")
    )
    db.session.add(c)
    db.session.commit()
    return {"message": "contact added", "contact": contact_dict(c)}

@app.route("/me/contacts", methods=["GET"])
@login_required
def list_contacts():
    if current_user.role != "patient":
        return {"error": "only patients allowed"}, 403
    contacts = EmergencyContact.query.filter_by(patient_uuid=current_user.patient.uuid).all()
    return {"contacts": [contact_dict(c) for c in contacts]}

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
@app.route("/patient/<string:uuid>", methods=["GET"])
def public_patient(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error": "not found"}, 404

    contacts = EmergencyContact.query.filter_by(patient_uuid=p.uuid).all()
    contact_html = "".join(
        [f"<li>{c.name} ({c.relation}) - {c.phone}</li>" for c in contacts]
    )

    html = f"""
    <html>
    <head>
        <title>Patient Info</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f9f9f9;
                color: #333;
            }}
            .card {{
                max-width: 500px;
                margin: auto;
                background: white;
                padding: 20px;
                border-radius: 12px;
                box-shadow: 0px 0px 10px rgba(0,0,0,0.1);
            }}
            h2 {{
                color: #2c3e50;
                text-align: center;
            }}
            p {{
                margin: 5px 0;
            }}
            ul {{
                padding-left: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2>Patient: {p.name}</h2>
            <p><strong>Age:</strong> {p.age}</p>
            <p><strong>Blood Group:</strong> {p.blood_group}</p>
            <p><strong>Allergies:</strong> {p.allergies if p.allergies else "None"}</p>
            <p><strong>Medications:</strong> {p.medications if p.medications else "None"}</p>
            <h3>Emergency Contacts:</h3>
            <ul>
                {contact_html if contact_html else "<li>No emergency contacts available</li>"}
            </ul>
        </div>

        <script>
        // 📍 Try to get live location
        if (navigator.geolocation) {{
            navigator.geolocation.getCurrentPosition(
                (pos) => {{
                    fetch('/report_location/{uuid}/live', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{
                            latitude: pos.coords.latitude,
                            longitude: pos.coords.longitude
                        }})
                    }});
                }},
                (err) => {{
                    console.error("Location permission denied:", err);
                    fetch('/report_location/{uuid}', {{method: 'POST'}});
                }}
            );
        }} else {{
            fetch('/report_location/{uuid}', {{method: 'POST'}});
        }}
        </script>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route("/report_location/<string:uuid>", methods=["POST"])
def report_location(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error":"patient not found"}, 404

    contacts = EmergencyContact.query.filter_by(patient_uuid=p.uuid).all()
    if contacts:
        scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        alert_msg = f"🚨 QR for {p.name} was scanned at {scan_time}."
        for c in contacts:
            send_sms(c.phone, alert_msg)

    return {"status": "ok"}

# ✅ ---------- LIVE LOCATION ROUTE ----------
@app.route("/report_location/<string:uuid>/live", methods=["POST"])
def report_live_location(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error":"patient not found"}, 404

    data = request.get_json() or {}
    lat = data.get("latitude")
    lon = data.get("longitude")

    if not lat or not lon:
        return {"error":"latitude and longitude required"}, 400

    contacts = EmergencyContact.query.filter_by(patient_uuid=p.uuid).all()
    if contacts:
        location_link = f"https://www.google.com/maps?q={lat},{lon}"
        scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        alert_msg = f"🚨 QR for {p.name} scanned at {scan_time}\n📍 Location: {location_link}"
        for c in contacts:
            send_sms(c.phone, alert_msg)

    return {"status": "ok", "message": "Live location sent to contacts"}

@app.route("/generate_qr/<string:uuid>", methods=["GET"])
def generate_qr(uuid):
    p = Patient.query.filter_by(uuid=uuid).first()
    if not p:
        return {"error":"not found"}, 404

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    url = f"http://{local_ip}:5000/patient/{uuid}"

    out = os.path.join(QRC_DIR, f"{uuid}.png")
    qrcode.make(url).save(out)

    rel = os.path.join("static","qrcodes", f"{uuid}.png").replace("\\","/")
    return {"qr": rel, "opens": url}

# ---------------- Init ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
