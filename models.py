import uuid
import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db

# ------------------ HOSPITAL ------------------
class Hospital(db.Model):
    __tablename__ = 'hospital'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)  # Unique hospital registration code
    verified = db.Column(db.Boolean, default=False)  # For real projects: mark as verified by admin

    staff_members = db.relationship("User", backref="hospital", lazy=True)


# ------------------ USER ------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="patient")  # 'patient' or 'staff'
    
    # link staff to hospital
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospital.id'), nullable=True)

    # one-to-one link: if user is patient → one Patient profile
    patient = db.relationship("Patient", backref="user", uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ------------------ PATIENT ------------------
class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))  # link to User

    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    blood_group = db.Column(db.String(10), nullable=False)
    allergies = db.Column(db.String(200), nullable=True)
    medications = db.Column(db.String(200), nullable=True)

    # relationships
    emergency_contacts = db.relationship("EmergencyContact", backref="patient", lazy=True)
    reports = db.relationship("Report", backref="patient", lazy=True)


# ------------------ EMERGENCY CONTACT ------------------
class EmergencyContact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_uuid = db.Column(db.String(36), db.ForeignKey("patient.uuid"))
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    relation = db.Column(db.String(50), nullable=False)


# ------------------ REPORT ------------------
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_uuid = db.Column(db.String(36), db.ForeignKey("patient.uuid"))
    filename = db.Column(db.String(255), nullable=False)  # path under static/reports/<uuid>/
    description = db.Column(db.String(300), nullable=True)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
