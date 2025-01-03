from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from io import BytesIO
from datetime import datetime
import pdfkit
import hashlib
import logging
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///barangay.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

db = SQLAlchemy(app)
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
    date_issued = db.Column(db.DateTime, default=datetime.utcnow)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_pdf_report(**data):
    try:
        config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
        html = render_template('analytics_report.html', **data)
        pdf = pdfkit.from_string(html, False, configuration=config)
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
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', role=role)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = Account.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home_screen'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/home')
@login_required
def home_screen():
    return render_template('HomeScreen.html', role=current_user.role)

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
            'user': ['delete_resident', 'manage_users'],  
        }
        if current_user.role not in restricted_routes:
            return
        if request.endpoint in restricted_routes.get(current_user.role, []):
            flash('You are not authorized to access this page.', 'danger')
            return redirect(url_for('home_screen'))


@app.route('/residents', methods=['GET'])
def index():
    query = request.args.get('query', '')
    if query:
        residents = Resident.query.filter(Resident.full_name.contains(query)).all()
    else:
        residents = Resident.query.all()
    return render_template('index.html', residents=residents, query=query)

@app.route('/add', methods=['GET', 'POST'])
def add_resident():
    if request.method == 'POST':
        full_name = request.form['full_name']
        address = request.form['address']
        occupation = request.form['occupation']
        purpose = request.form['purpose']
        resident = Resident(full_name=full_name, address=address, occupation=occupation, purpose=purpose)
        db.session.add(resident)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_resident.html')

@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_resident(id):
    if current_user.role != 'admin':
        flash('You are not authorized to delete residents.', 'danger')
        return redirect(url_for('index'))

    resident = Resident.query.get_or_404(id)
    db.session.delete(resident)
    db.session.commit()
    flash(f"Resident {resident.full_name} has been deleted.", 'success')
    return redirect(url_for('index'))


@app.route('/generate/<int:id>')
def generate(id):
    resident = Resident.query.get_or_404(id)
    data = {
        'full_name': resident.full_name,
        'address': resident.address,
        'occupation': resident.occupation,
        'purpose': resident.purpose,
        'date': datetime.now().strftime('%B %d, %Y')
    }

    base_url = request.url_root

    try:
        config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
        html = render_template('certificate_template.html', base_url=base_url, **data)
        pdf = pdfkit.from_string(html, False, configuration=config)
        return send_file(BytesIO(pdf), as_attachment=True, download_name=f"Indigency_Certificate_{resident.full_name}.pdf")
    except Exception as e:
        logging.error(f"PDF generation failed: {e}")
        flash("Error generating PDF. Please contact support.", "danger")
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




if __name__ == '__main__':
    if not os.path.exists('barangay.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)

for rule in app.url_map.iter_rules():
    print(rule)
