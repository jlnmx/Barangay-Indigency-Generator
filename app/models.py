from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Resident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    date_issued = db.Column(db.DateTime, default=datetime.utcnow)
    approval_status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'

    def __repr__(self):
        return f'<Resident {self.full_name}>'

class ApprovalLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resident_id = db.Column(db.Integer, db.ForeignKey('resident.id'), nullable=False)
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'

    resident = db.relationship('Resident', backref=db.backref('approvals', lazy=True))

    def __repr__(self):
        return f'<ApprovalLog {self.id} for Resident {self.resident.full_name}>'