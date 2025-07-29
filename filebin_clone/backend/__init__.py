from flask import Flask
from backend.extensions import db
from api.routes import bp as api_bp
from backend.extensions import jwt
from api.auth import auth_bp
from frontend.main import main as frontend_bp
from flask_cors import CORS
def create_app():
    app = Flask(__name__)
    app.secret_key = "your_super_secret_key_here" 
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///filebin.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = 'your-secret-key'
    CORS(app, supports_credentials=True)
    jwt.init_app(app)
    db.init_app(app)

    from backend.models import Bin, File
    with app.app_context():
        db.create_all()

    from api.routes import bp as api_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(frontend_bp)
    return app
