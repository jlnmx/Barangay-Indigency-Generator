from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash
from flask_mail import Mail, Message
from .models import db, Resident
from flask_login import current_user

bp = Blueprint('routes', __name__)
mail = Mail()

@bp.route('/home')
def home_screen():
    pending_approvals = Resident.query.filter_by(approval_status='pending').all()
    return render_template('homescreen.html', pending_approvals=pending_approvals)

@bp.route('/approval', methods=['GET', 'POST'])
def approval():
    if request.method == 'POST':
        resident_id = request.form.get('resident_id')
        action = request.form.get('action')
        resident = Resident.query.get(resident_id)

        if action == 'approve':
            resident.approval_status = 'approved'
            db.session.commit()
            flash('Resident approved successfully.', 'success')
        elif action == 'reject':
            resident.approval_status = 'rejected'
            db.session.commit()
            flash('Resident rejected successfully.', 'danger')

        send_notification_email(resident)
        return redirect(url_for('routes.approval'))

    residents = Resident.query.filter_by(approval_status='pending').all()
    return render_template('approval.html', residents=residents)

def send_notification_email(resident):
    msg = Message('Pending Approval Notification',
                  sender='your_email@example.com',
                  recipients=['staff_email@example.com'])
    msg.body = f'Resident {resident.full_name} is pending approval.'
    mail.send(msg)

@bp.route('/add', methods=['GET', 'POST'])
def add_resident():
    if request.method == 'POST':
        full_name = request.form['full_name']
        address = request.form['address']
        occupation = request.form['occupation']
        purpose = request.form['purpose']
        new_resident = Resident(full_name=full_name, address=address, occupation=occupation, purpose=purpose, approval_status='pending')
        db.session.add(new_resident)
        db.session.commit()
        return jsonify({"success": True, "message": "Resident added successfully"})
    return render_template('add_resident.html')