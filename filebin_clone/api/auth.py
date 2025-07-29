import uuid
import re
from flask import request, render_template, Blueprint, jsonify
from backend.models import db, User
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    # Check if JSON data was provided
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    username = data.get("username")
    password = data.get("password")
    
    # Check if required fields are provided
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Validation pattern - only letters and numbers, minimum 4 characters
    pattern = r'^[A-Za-z0-9]{4,}$'
    
    if not re.match(pattern, username):
        return jsonify({'error': 'Invalid username format. Must be at least 4 characters and contain only letters and digits.'}), 400

    if not re.match(pattern, password):
        return jsonify({'error': 'Invalid password format. Must be at least 4 characters and contain only letters and digits.'}), 400

    # Check if user exists and password is correct
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Optional: Check if user is already logged in from another device
    # if user.logged_in:
    #     return jsonify({"error": "User already logged in from another device"}), 403
    
    try:
        # ✅ Create new session token
        new_session_token = str(uuid.uuid4())
        user.session_token = new_session_token
        user.logged_in = True
        db.session.commit()

        # ✅ Create access token with session_token in claims
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={"session_token": new_session_token}
        )

        return jsonify({'access_token': access_token}), 200
    
    except Exception as e:
        db.session.rollback()
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed due to server error'}), 500


@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    # Check if JSON data was provided
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    username = data.get("username")
    password = data.get("password")
    
    # Check if required fields are provided
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    # Validation pattern - only letters and numbers, minimum 4 characters
    pattern = r'^[A-Za-z0-9]{4,}$'
    
    if not re.match(pattern, username):
        return jsonify({"error": "Invalid username format. Must be at least 4 characters and contain only letters and digits."}), 400

    if not re.match(pattern, password):
        return jsonify({"error": "Invalid password format. Must be at least 4 characters and contain only letters and digits."}), 400

    try:
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 409

        # Hash the password
        hashed_pw = generate_password_hash(password)

        # Create and save the user
        new_user = User(username=username, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "User created successfully"}), 201
    
    except Exception as e:
        db.session.rollback()
        print(f"Signup error: {e}")
        return jsonify({"error": "Failed to create user"}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        # Get current user from JWT
        current_user_id = get_jwt_identity()
        claims = get_jwt()  # ✅ Now properly imported
        session_token = claims.get('session_token')
        
        # Update user status in database
        user = User.query.get(current_user_id)
        if user and user.session_token == session_token:
            user.logged_in = False
            user.session_token = None
            db.session.commit()
            
        return jsonify({'message': 'Successfully logged out'}), 200
    
    except Exception as e:
        db.session.rollback()
        print(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        current_user_id = get_jwt_identity()
        claims = get_jwt()  # ✅ Now properly imported
        session_token = claims.get('session_token')
        
        # Verify session token matches database
        user = User.query.get(current_user_id)
        if not user or user.session_token != session_token or not user.logged_in:
            return jsonify({'error': 'Invalid session'}), 401
            
        return jsonify({
            'valid': True, 
            'user_id': current_user_id,
            'username': user.username
        }), 200
    
    except Exception as e:
        print(f"Token verification error: {e}")
        return jsonify({'error': 'Token verification failed'}), 401


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    try:
        user_id = get_jwt_identity()
        claims = get_jwt()  # ✅ Now properly imported
        session_token = claims.get('session_token')
        
        user = User.query.get(user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Verify session token for extra security
        if user.session_token != session_token or not user.logged_in:
            return jsonify({"error": "Invalid session"}), 401

        return jsonify({
            "id": user.id,
            "username": user.username,
            "logged_in": user.logged_in
            # Add other non-sensitive fields as needed
        }), 200
    
    except Exception as e:
        print(f"Get current user error: {e}")
        return jsonify({"error": "Failed to get user information"}), 500


# Optional: Route to refresh token
@auth_bp.route('/refresh', methods=['POST'])
@jwt_required()
def refresh_token():
    try:
        current_user_id = get_jwt_identity()
        claims = get_jwt()
        session_token = claims.get('session_token')
        
        # Verify user and session
        user = User.query.get(current_user_id)
        if not user or user.session_token != session_token or not user.logged_in:
            return jsonify({'error': 'Invalid session'}), 401
        
        # Create new access token with same session token
        new_access_token = create_access_token(
            identity=str(user.id),
            additional_claims={"session_token": session_token}
        )
        
        return jsonify({'access_token': new_access_token}), 200
    
    except Exception as e:
        print(f"Token refresh error: {e}")
        return jsonify({'error': 'Token refresh failed'}), 500