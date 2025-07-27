
import uuid
import re
from flask import request, render_template
from flask import Blueprint, request, jsonify
from backend.models import db, User
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash
from flask_jwt_extended import jwt_required, get_jwt_identity
from backend.models import db, User

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    pattern = r'[A-Za-z0-9]{4,}'
    if not re.fullmatch(pattern, username):
        return render_template("login.html", error="❌ Invalid username.")

    if not re.fullmatch(pattern, password):
        return render_template("login.html", error="❌ Invalid password.")

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
   # if user.logged_in:
    #    return jsonify({"msg": "User already logged in from another device"}), 403
    # ✅ New session token
    new_session_token = str(uuid.uuid4())
    user.session_token = new_session_token
    user.logged_in = True
    db.session.commit()

    # ✅ Encode session_token in JWT identity
  
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"session_token": new_session_token}
    )

    return jsonify({'access_token': access_token}), 200

# api/auth.py





@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not re.fullmatch(r'[A-Za-z0-9]{4,}', username):
        return render_template("signup.html", error="❌ Invalid username. Only letters/digits, min 4 characters.")

    if not re.fullmatch(r'[A-Za-z0-9]{4,}', password):
        return render_template("signup.html", error="❌ Invalid password. Only letters/digits, min 4 characters.")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Check if user already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already taken"}), 409

    # Hash the password
    hashed_pw = generate_password_hash(password)

    # Create and save the user
    new_user = User(username=username, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully"}), 201

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    user.logged_in = False
    user.session_token = None
    db.session.commit()

    return jsonify({"msg": "Logged out successfully"}), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        # include other info if needed (but avoid sensitive fields like passwords)
    }), 200