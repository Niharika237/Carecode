from app import app, db
from models import Hospital

with app.app_context():
    h1 = Hospital(name="Apollo Hospitals", email="contact@apollo.com", code="APOLLO123", verified=True)
    h2 = Hospital(name="Fortis Hospital", email="admin@fortis.com", code="FORTIS456", verified=True)
    h3 = Hospital(name="Narayana Health", email="info@narayana.com", code="NH789", verified=True)

    db.session.add_all([h1, h2, h3])
    db.session.commit()

    print("✅ Hospitals added successfully!")
    for h in Hospital.query.all():
        print(h.name, h.code)
