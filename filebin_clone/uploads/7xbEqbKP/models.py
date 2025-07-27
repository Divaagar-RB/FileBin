from . import db
from datetime import datetime
from passlib.hash import pbkdf2_sha256 as sha256

class Bin(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    bin_id = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='bin', lazy=True, cascade="all, delete")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='bins')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bin_id = db.Column(db.String(8), db.ForeignKey('bin.bin_id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)



class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    session_token = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    logged_in = db.Column(db.Boolean, default=False)

    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    @staticmethod
    def verify_hash(password, hash_):
        return sha256.verify(password, hash_)
