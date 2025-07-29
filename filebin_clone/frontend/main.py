from flask import Blueprint, render_template, request, redirect, url_for, session
import requests
import jwt
from datetime import datetime
main = Blueprint("main", __name__, template_folder="templates")

API_URL = "http://localhost:5000"  # adjust to your API host/port


@main.route('/')
def home():
    return redirect(url_for('main.login_page'))
@main.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Basic validation on frontend
    if not username or not password:
        return render_template('login.html', error="Username and password are required")
    
    try:
        # Make API call to your backend
        res = requests.post('http://127.0.0.1:5000/auth/login',  # Update with your actual backend URL
                          json={'username': username, 'password': password},
                          headers={'Content-Type': 'application/json'},
                          timeout=10)
        
        print(f"Response status: {res.status_code}")
        print(f"Response body: {res.text}")  # Debug log
        
        # Handle successful login
        if res.status_code == 200:
            try:
                json_data = res.json()
                access_token = json_data.get('access_token')
                if access_token:
                    session['access_token'] = access_token
                    
                    # Check if user was trying to access a protected page before login
                    next_url = request.args.get('next')
                    if next_url:
                        return redirect(next_url)
                    return redirect(url_for('main.dashboard'))
                else:
                    return render_template('login.html', error="Authentication failed: No token received")
            except ValueError:
                return render_template('login.html', error="Invalid server response")
        
        # Handle error responses
        else:
            try:
                error_data = res.json()
                error_message = error_data.get('error', 'Authentication failed')
            except ValueError:
                # If response is not JSON, use generic message
                if res.status_code == 400:
                    error_message = "Invalid request format"
                elif res.status_code == 401:
                    error_message = "Invalid credentials"
                elif res.status_code == 403:
                    error_message = "Access forbidden"
                elif res.status_code == 500:
                    error_message = "Server error occurred"
                else:
                    error_message = f"Authentication failed (Status: {res.status_code})"
            
            return render_template('login.html', error=error_message)
    
    except requests.exceptions.Timeout:
        return render_template('login.html', error="Request timed out. Please try again.")
    except requests.exceptions.ConnectionError:
        return render_template('login.html', error="Unable to connect to authentication server")
    except Exception as e:
        print(f"Unexpected error: {e}")
        return render_template('login.html', error="An unexpected error occurred")
@main.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@main.route('/signup', methods=['GET']) 
def signup_page(): 
    return render_template('signup.html')
@main.route('/signup', methods=['POST']) 
def signup(): 
    try:
        # Validate form data exists
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Input validation
        if not username:
            return render_template("signup.html", error="Username is required")
        if not password:
            return render_template("signup.html", error="Password is required")
        if len(username) < 4:
            return render_template("signup.html", error="Username must be at least 4 characters")
        if len(password) < 4:
            return render_template("signup.html", error="Password must be at least 4 characters")
        
        data = { 
            "username": username, 
            "password": password 
        }
        
        # Make API call
        res = requests.post(f"{API_URL}/auth/signup", 
                          json=data,
                          headers={'Content-Type': 'application/json'},
                          timeout=15)
        
        # Log response for debugging
        print(f"Signup API response - Status: {res.status_code}, Body: {res.text}")
        
        # Success case
        if res.status_code == 201:
            # You could add a success message and redirect
            return redirect(url_for('main.login_page'))
        
        # Handle specific error cases
        elif res.status_code == 400:
            try:
                error_data = res.json()
                error_message = error_data.get('error', 'Invalid input data')
            except ValueError:
                error_message = "Invalid username or password format"
        
        elif res.status_code == 409:
            error_message = "Username already exists. Please choose a different username."
        
        elif res.status_code == 500:
            error_message = "Server error. Please try again later."
        
        else:
            try:
                error_data = res.json()
                error_message = error_data.get('error', f'Signup failed with status {res.status_code}')
            except ValueError:
                error_message = f"Signup failed. Please try again. (Error {res.status_code})"
        
        return render_template("signup.html", error=error_message)
    
    except requests.exceptions.Timeout:
        error_message = "Request timed out. The server might be busy. Please try again."
        return render_template("signup.html", error=error_message)
    
    except requests.exceptions.ConnectionError:
        error_message = "Cannot connect to the server. Please check your internet connection."
        return render_template("signup.html", error=error_message)
    
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error during signup: {e}")
        error_message = "Server error occurred. Please try again later."
        return render_template("signup.html", error=error_message)
    
    except requests.exceptions.RequestException as e:
        print(f"Request exception during signup: {e}")
        error_message = "Network error. Please check your connection and try again."
        return render_template("signup.html", error=error_message)
    
    except ValueError as e:
        print(f"Value error during signup: {e}")
        error_message = "Invalid data format. Please try again."
        return render_template("signup.html", error=error_message)
    
    except Exception as e:
        print(f"Unexpected error during signup: {e}")
        error_message = "An unexpected error occurred. Please try again."
        return render_template("signup.html", error=error_message)


@main.route('/dashboard')
def dashboard():
    try:
        token = session.get('access_token')
        if not token:
            return redirect(url_for('main.login_page'))
        
        # Optional: Validate token with backend
        try:
            # Verify token is still valid by making a test API call
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(f"{API_URL}/auth/verify", 
                                  headers=headers, 
                                  timeout=5)
            
            if response.status_code == 401:
                # Token is invalid/expired
                session.pop('access_token', None)
                return redirect(url_for('main.login_page'))
            elif response.status_code != 200:
                # Other API errors - still show dashboard but log the issue
                print(f"Token verification failed with status {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            # Network error - still allow access but log the issue
            print(f"Token verification request failed: {e}")
        
        # Get user info from token (optional)
        try:
            # Decode JWT to get user info (without verification for display purposes)
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            user_id = decoded_token.get('sub')  # 'sub' is typically the user ID
            session_token = decoded_token.get('session_token')
            exp = decoded_token.get('exp')
            
            # Check if token is expired
            if exp and datetime.utcnow().timestamp() > exp:
                session.pop('access_token', None)
                return redirect(url_for('main.login_page'))
            
            # Pass user info to template
            return render_template("dashboard.html", 
                                 user_id=user_id, 
                                 session_token=session_token)
        
        except jwt.InvalidTokenError:
            # Token is malformed
            session.pop('access_token', None)
            return redirect(url_for('main.login_page'))
        
        except Exception as e:
            print(f"Error decoding token: {e}")
            # Still render dashboard even if token decoding fails
            return render_template("dashboard.html")
    
    except Exception as e:
        print(f"Unexpected error in dashboard: {e}")
        return redirect(url_for('main.login_page'))


@main.route('/logout', methods=['POST'])
def logout():
    try:
        token = session.get('access_token')
        
        # Notify backend about logout (optional but recommended)
        if token:
            try:
                headers = {'Authorization': f'Bearer {token}'}
                response = requests.post(f"{API_URL}/auth/logout", 
                                       headers=headers, 
                                       timeout=5)
                
                if response.status_code == 200:
                    print("Successfully logged out from backend")
                else:
                    print(f"Backend logout failed with status {response.status_code}")
            
            except requests.exceptions.RequestException as e:
                print(f"Backend logout request failed: {e}")
                # Continue with frontend logout even if backend fails
        
        # Clear session
        session.pop("access_token", None)
        # Optional: Clear entire session
        # session.clear()
        
        return redirect(url_for("main.login_page"))
    
    except Exception as e:
        print(f"Error during logout: {e}")
        # Even if there's an error, clear the session and redirect
        session.clear()
        return redirect(url_for("main.login_page"))



# Helper function to check if user is authenticated
def require_auth():
    """Decorator function to require authentication"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            token = session.get('access_token')
            if not token:
                return redirect(url_for('main.login_page'))
            
            # Optional: Verify token is still valid
            try:
                decoded_token = jwt.decode(token, options={"verify_signature": False})
                exp = decoded_token.get('exp')
                if exp and datetime.utcnow().timestamp() > exp:
                    session.pop('access_token', None)
                    return redirect(url_for('main.login_page'))
            except jwt.InvalidTokenError:
                session.pop('access_token', None)
                return redirect(url_for('main.login_page'))
            
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


# Usage example with the decorator
@main.route('/dashboard')
@require_auth()
def dashboard_with_decorator():
    try:
        token = session.get('access_token')
        
        # Get user info from token
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            user_id = decoded_token.get('sub')
            
            return render_template("dashboard.html", user_id=user_id)
        
        except Exception as e:
            print(f"Error decoding token: {e}")
            return render_template("dashboard.html")
    
    except Exception as e:
        print(f"Unexpected error in dashboard: {e}")
        return redirect(url_for('main.login_page'))


# Route to check authentication status (useful for AJAX calls)
@main.route('/auth/status')
def auth_status():
    try:
        token = session.get('access_token')
        if not token:
            return {"authenticated": False}, 401
        
        # Verify token
        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            exp = decoded_token.get('exp')
            if exp and datetime.utcnow().timestamp() > exp:
                session.pop('access_token', None)
                return {"authenticated": False, "reason": "expired"}, 401
            
            return {"authenticated": True, "user_id": decoded_token.get('sub')}, 200
        
        except jwt.InvalidTokenError:
            session.pop('access_token', None)
            return {"authenticated": False, "reason": "invalid"}, 401
    
    except Exception as e:
        print(f"Error checking auth status: {e}")
        return {"authenticated": False, "reason": "error"}, 500
@main.route('/view/bin/<bin_id>')
def view_bin(bin_id):
    token = session.get("access_token")
    if not token:
        return redirect(url_for("main.login_page", next=request.path))

    headers = {"Authorization": f"Bearer {token}"}

    # Step 1: Get current user info
    me_res = requests.get(f"{API_URL}/auth/me", headers=headers)
    if me_res.status_code != 200:
        session.pop("access_token", None)
        return redirect(url_for("main.login_page", next=request.path))
    current_user = me_res.json()
    current_user_id = str(current_user["id"])

    # Step 2: Get bin info
    bin_res = requests.get(f"{API_URL}/bin/{bin_id}", headers=headers)
    if bin_res.status_code != 200:
        return render_template("bin.html", bin_id=bin_id, files=[], error="Bin not found")

    bin_data = bin_res.json()
    bin_owner_id = str(bin_data.get("user_id"))

    is_owner = (current_user_id == bin_owner_id)
    print(current_user_id)
    print(bin_owner_id)
    return render_template("bin.html", bin_id=bin_id, files=bin_data["files"], is_owner=is_owner)
