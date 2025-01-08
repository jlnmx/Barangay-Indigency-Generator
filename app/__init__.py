from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

def create_app():
      app = Flask(__name__, static_folder='static')

      app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///barangay.db' 
      app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
      app.secret_key = 'your_secret_key' 

      db.init_app(app)
      migrate.init_app(app, db)
      mail.init_app(app)

      from .routes import bp as routes_bp
      app.register_blueprint(routes_bp)
        
      return app
     
