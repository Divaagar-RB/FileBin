from flask import Blueprint, render_template, request, redirect, url_for, session
import requests

main = Blueprint("main", __name__, template_folder="templates")

API_URL = "http://localhost:5000"  # adjust to your API host/port


@main.route('/')
def home():
    return redirect(url_for('main.login_page'))

@main.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@main.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')
@main.route('/login', methods=['POST'])
def login():
    data = {
        "username": request.form['username'],
        "password": request.form['password']
    }

    print("Sending credentials to API...")
    res = requests.post(f"{API_URL}/auth/login", json=data)
    print("API Response Code:", res.status_code)
    print("API Response Body:", res.text)

    if res.status_code == 200:
        session['access_token'] = res.json()['access_token']
        print("✅ Login successful! Redirecting...")
          # Check if user was trying to access a protected page before login
        next_url = request.args.get('next')
        if next_url:
            return redirect(next_url)
        return redirect(url_for('main.dashboard'))  
        

    print("❌ Login failed")
    return render_template("login.html", error="Invalid credentials")


@main.route('/signup', methods=['POST'])
def signup():
    data = {
        "username": request.form['username'],
        "password": request.form['password']
    }
    res = requests.post(f"{API_URL}/auth/signup", json=data)
    if res.status_code == 201:
        return redirect(url_for('main.login_page'))
  
    return render_template("signup.html", error="User already exists")

@main.route('/dashboard')
def dashboard():
    token = session.get('access_token')
    if not token:
        return redirect(url_for('main.login_page'))  # Not logged in
    return render_template("dashboard.html")


@main.route('/logout', methods=['POST'])
def logout():
    session.pop("access_token", None)
    return redirect(url_for("main.login_page"))

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
