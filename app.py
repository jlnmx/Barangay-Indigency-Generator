from flask import Flask, jsonify, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from io import BytesIO
from datetime import datetime
import pdfkit
import hashlib
import logging
import os

app = Flask(__name__, static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///barangay.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'barangayindigencycertsystem@gmail.com'  
app.config['MAIL_PASSWORD'] = 'xzjv fymj qogl kccj'


db = SQLAlchemy(app)
mail = Mail(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))

class Account(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False)

class Resident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    date_requested = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_issued = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='pending')  

    approvals = db.relationship('ApprovalLog', backref='resident', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Resident {self.full_name}>'

    def __init__(self, full_name, address, occupation, purpose, date_requested=None):
        self.full_name = full_name
        self.address = address
        self.occupation = occupation
        self.purpose = purpose
        if date_requested is None:
            date_requested = datetime.utcnow()
        self.date_requested = date_requested

class ApprovalLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resident_id = db.Column(db.Integer, db.ForeignKey('resident.id'), nullable=False)
    approved_by = db.Column(db.String(100), nullable=False)
    approval_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False) 

    def __repr__(self):
        return f'<ApprovalLog {self.id} - {self.status}>'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_pdf_report(**data):
    try:
        config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
        html = render_template('analytics_report.html', **data)
        pdf = pdfkit.from_string(html, False, configuration=config, options={'enable-local-file-access': True})
        return BytesIO(pdf)
    except Exception as e:
        logging.error(f"Error generating report: {e}, Data: {data}")
        raise

@app.route('/')
def entry_point():
    return render_template('entry_point.html')

@app.route('/register/<role>', methods=['GET', 'POST'])
def register(role):
    if role not in ['admin', 'user']:
        return redirect(url_for('entry_point'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        
        if Account.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register', role=role))
        
        user = Account(username=username, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        flash('Account created successfully! You are now logged in.', 'success')
        return redirect(url_for('home_screen'))
    
    return render_template('register.html', role=role)

@app.route('/login', methods=['GET', 'POST'])
def login():
    role = request.args.get('role', 'user') 
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Account.query.filter_by(username=username, role=role).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome {user.username}!", "success")
            return redirect(url_for('home_screen'))
        else:
            flash("Incorrect username or password or role mismatch. Please try again.", "danger")
    
    return render_template('login.html', role=role)

@app.route('/home')
@login_required
def home_screen():
    pending_approvals = Resident.query.filter_by(status='pending').all()
    return render_template('HomeScreen.html', role=current_user.role, pending_approvals=pending_approvals)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('entry_point'))

@app.before_request
def restrict_access():
    if current_user.is_authenticated:
        restricted_routes = {
            'admin': [], 
            'user': ['manage_users'],  
        }
        if current_user.role not in restricted_routes:
            return
        if request.endpoint in restricted_routes.get(current_user.role, []):
            flash('You are not authorized to access this page.', 'danger')
            return redirect(url_for('home_screen'))

@app.route('/approval')
@login_required
def approval():
    pending_residents = Resident.query.filter_by(status='pending').all()
    return render_template('approval.html', residents=pending_residents)

@app.route('/approve/<int:resident_id>', methods=['POST'])
@login_required
def approve_request(resident_id):
    if current_user.role != 'admin':
        flash('You are not authorized to approve requests.', 'danger')
        return redirect(url_for('approval'))

    resident = Resident.query.get_or_404(resident_id)
    resident.status = 'approved'
    db.session.commit()
    flash('Request approved successfully.', 'success')
    return redirect(url_for('approval'))

@app.route('/reject/<int:resident_id>', methods=['POST'])
@login_required
def reject_request(resident_id):
    if current_user.role != 'admin':
        flash('You are not authorized to reject requests.', 'danger')
        return redirect(url_for('approval'))

    resident = Resident.query.get_or_404(resident_id)
    resident.status = 'rejected'
    db.session.commit()
    flash('Request rejected successfully.', 'success')
    return redirect(url_for('approval'))

@app.route('/rejected_requests')
@login_required
def rejected_requests():
    rejected_residents = Resident.query.filter_by(status='rejected').all()
    return render_template('rejected_requests.html', rejected_residents=rejected_residents)

@app.route('/residents', methods=['GET'])
def index():
    query = request.args.get('query', '')
    purpose_filter = request.args.get('purpose', '')

    residents = Resident.query.filter_by(status="approved")

    if query:
        residents = residents.filter(Resident.full_name.contains(query))
    if purpose_filter:
        residents = residents.filter(Resident.purpose == purpose_filter)

    residents = residents.all()

    purposes = [purpose[0] for purpose in db.session.query(Resident.purpose).distinct().all()]

    return render_template(
        'index.html',
        residents=residents,
        query=query,
        purpose_filter=purpose_filter,
        purposes=purposes,
    )

@app.route('/update_resident/<int:id>', methods=['POST'])
@login_required
def update_resident(id):
    data = request.get_json()  
    resident = Resident.query.get_or_404(id)

    try:
        if 'full_name' in data:
            resident.full_name = data['full_name']
        if 'address' in data:
            resident.address = data['address']
        if 'occupation' in data:
            resident.occupation = data['occupation']
        if 'purpose' in data:
            resident.purpose = data['purpose']

        db.session.commit()  
        return jsonify({"success": True, "message": "Resident updated successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": "An error occurred while updating the resident."}), 500

@app.route('/add', methods=['GET', 'POST'])
def add_resident():
    if request.method == 'POST':
        full_name = request.form['full_name']
        address = request.form['address']
        occupation = request.form['occupation']
        purpose = request.form['purpose']

        existing_resident = Resident.query.filter_by(full_name=full_name).first()
        if existing_resident:
            flash('Resident Record Already Exists', 'danger')
            return render_template('add_resident.html')

        new_resident = Resident(full_name=full_name, address=address, occupation=occupation, purpose=purpose)
        db.session.add(new_resident)
        try:
            db.session.commit()
            try:
                msg = Message('New Pending Resident Indigency Request Added', sender='barangayindigencycertsystem@gmail.com', recipients=['ajlabre14@gmail.com'])
                msg.body = f'A new resident has been added:\n\nFull Name: {full_name}\nAddress: {address}\nOccupation: {occupation}\nPurpose: {purpose}'
                mail.send(msg)
                flash('Resident added successfully!', 'success')
            except Exception as e:
                flash(f'Failed to send email notification: {str(e)}', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to add resident: {str(e)}', 'danger')

        return render_template('add_resident.html')

    return render_template('add_resident.html')

@app.route('/delete/<int:resident_id>', methods=['POST'])
def delete_resident(resident_id):
    resident = Resident.query.get_or_404(resident_id)
    
    ApprovalLog.query.filter_by(resident_id=resident_id).delete()
    
    db.session.delete(resident)
    db.session.commit()
    flash(f'Resident {resident.full_name} has been deleted successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/generate/<int:id>')
@login_required
def generate(id):
    resident = Resident.query.get_or_404(id)
    resident.date_issued = datetime.now()
    db.session.commit()

    data = {
        'full_name': resident.full_name,
        'address': resident.address,
        'occupation': resident.occupation,
        'purpose': resident.purpose,
        'date': resident.date_issued.strftime('%B %d, %Y')
    }

    try:
        base_url = request.url_root.replace('localhost', '127.0.0.1')
        html = render_template('certificate_template.html', base_url=base_url, **data)
        config = pdfkit.configuration(wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe")

        pdf = pdfkit.from_string(
            html,
            False,
            configuration=config,
            options={'enable-local-file-access': True}
        )
        return send_file(BytesIO(pdf), as_attachment=True, download_name=f"Indigency_Certificate_{resident.full_name}.pdf")
    except Exception as e:
        logging.error(f"PDF generation failed: {e}")
        flash("An error occurred while generating the certificate.", "danger")
        return redirect(url_for('index'))

@app.route('/analytics')
def analytics():
    total_residents = Resident.query.count()

    purposes = [(p, Resident.query.filter_by(purpose=p).count()) for p in set(r.purpose for r in Resident.query.all())]
    occupations = [(o, Resident.query.filter_by(occupation=o).count()) for o in set(r.occupation for r in Resident.query.all())]

    purpose_labels = [p[0] for p in purposes]
    purpose_counts = [p[1] for p in purposes]
    purpose_percentages = [round((count / total_residents) * 100, 2) for count in purpose_counts]

    occupation_labels = [o[0] for o in occupations]
    occupation_counts = [o[1] for o in occupations]
    occupation_percentages = [round((count / total_residents) * 100, 2) for count in occupation_counts]

    return render_template(
        'analytics.html',
        total_residents=total_residents,
        purpose_labels=purpose_labels,
        purpose_counts=purpose_counts,
        purpose_percentages=purpose_percentages,
        occupation_labels=occupation_labels,
        occupation_counts=occupation_counts,
        occupation_percentages=occupation_percentages,
        zip=zip 
    )

@app.route('/analytics/download')
def download_report():
    total_residents = Resident.query.count()

    purposes = [(p, Resident.query.filter_by(purpose=p).count()) for p in set(r.purpose for r in Resident.query.all())]
    purpose_data = [
        {"label": p[0], "count": p[1], "percentage": round((p[1] / total_residents) * 100, 2)} 
        for p in purposes
    ]

    occupations = [(o, Resident.query.filter_by(occupation=o).count()) for o in set(r.occupation for r in Resident.query.all())]
    occupation_data = [
        {"label": o[0], "count": o[1], "percentage": round((o[1] / total_residents) * 100, 2)} 
        for o in occupations
    ]

    pdf = generate_pdf_report(
        total_residents=total_residents,
        purpose_data=purpose_data,
        occupation_data=occupation_data,
    )

    return send_file(pdf, as_attachment=True, download_name="IndigencyAnalyticalReport.pdf")

@app.route('/manage_users', methods=['GET'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('You are not authorized to manage users.', 'danger')
        return redirect(url_for('home_screen'))
    users = Account.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin':
        flash('You are not authorized to add users.', 'danger')
        return redirect(url_for('manage_users'))
    
    username = request.form['username']
    password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
    role = request.form['role']

    if Account.query.filter_by(username=username).first():
        flash('Username already exists!', 'danger')
        return redirect(url_for('manage_users'))

    new_user = Account(username=username, password=password, role=role)
    db.session.add(new_user)
    db.session.commit()
    flash('User added successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('You are not authorized to delete users.', 'danger')
        return redirect(url_for('manage_users'))

    user = Account.query.get_or_404(user_id)
    if user.role == 'admin':
        flash('You cannot delete an admin user.', 'danger')
        return redirect(url_for('manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} has been deleted.", 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Account.query.filter_by(username=username, role='admin').first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f"Welcome {user.username}!", "success")
            return redirect(url_for('home_screen'))
        else:
            flash("Incorrect username or password. Please try again.", "danger")
    
    return render_template('admin_login.html')

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        
        if Account.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('admin_register'))
        
        user = Account(username=username, password=password, role='admin')
        db.session.add(user)
        db.session.commit()
        
        login_user(user)
        flash('Admin account created successfully! You are now logged in.', 'success')
        return redirect(url_for('home_screen'))
    
    return render_template('admin_register.html')

if __name__ == '__main__':
    if not os.path.exists('barangay.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)

for rule in app.url_map.iter_rules():
    print(rule)