from flask import Flask, render_template, request, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from io import BytesIO
from datetime import datetime
import pdfkit
import os
import logging
from collections import Counter

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///barangay.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

db = SQLAlchemy(app)

class Resident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    occupation = db.Column(db.String(100), nullable=False)
    purpose = db.Column(db.String(200), nullable=False)
    date_issued = db.Column(db.DateTime, default=datetime.utcnow)

logging.basicConfig(level=logging.DEBUG)

def generate_certificate(data):
    try:
        config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
        html = render_template('certificate_template.html', **data)
        pdf = pdfkit.from_string(html, False, configuration=config)
        return BytesIO(pdf)
    except Exception as e:
        logging.error(f"Error generating certificate: {e}, Data: {data}")
        raise

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"An error occurred: {e}")
    return render_template("500.html"), 500

@app.route('/')
def home_screen():
    return render_template('HomeScreen.html')

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
    pdf = generate_certificate(data)
    return send_file(pdf, as_attachment=True, download_name=f"Indigency_Certificate_{resident.full_name}.pdf")

@app.route('/delete/<int:id>')
def delete(id):
    resident = Resident.query.get_or_404(id)
    db.session.delete(resident)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/analytics')
def analytics():
    residents = Resident.query.all()
    total_residents = len(residents)
    purposes = [resident.purpose for resident in residents]
    most_common_purpose = Counter(purposes).most_common(1)[0] if purposes else ("None", 0)

    return render_template('analytics.html', total_residents=total_residents, most_common_purpose=most_common_purpose)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    if not os.path.exists('barangay.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
