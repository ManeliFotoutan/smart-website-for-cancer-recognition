from flask import Flask, render_template, redirect, url_for, request, session, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
from forms import UserForm, LoginForm, OTPForm  
from OTP import send_code

app = Flask(__name__)
csrf = CSRFProtect(app)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(12)

db = SQLAlchemy(app)

# User model
class User(db.Model):
    __tablename__ = "User"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)

# Create database
with app.app_context():
    db.create_all()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You need to be logged in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/our-team')
def our_team():
    return render_template('our-team.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        if User.query.filter_by(username=username).first():
            flash('Username already taken, please choose another one.', 'warning')
            return redirect(url_for('register'))

        session['username'] = username
        session['email'] = email
        session['password'] = password
        otp_code = send_code(email)
        resp = make_response(redirect(url_for('otp')))
        resp.set_cookie('otp_code', str(otp_code))
        return resp

    return render_template("register.html", form=form)

# OTP validation function
def otp_code_isvalid(code):
    encrypted_otp_code = request.cookies.get('otp_code')
    return encrypted_otp_code and int(encrypted_otp_code) == code

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    form = OTPForm()
    if form.validate_on_submit():
        code = int(f"{form.otp1.data}{form.otp2.data}{form.otp3.data}{form.otp4.data}")

        if otp_code_isvalid(code):
            username = session.get('username')
            email = session.get('email')
            password = session.get('password')

            if username and password and email:
                hashed_password = generate_password_hash(password)
                new_user = User(username=username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()

                session.pop('username', None)
                session.pop('password', None)
                session.pop('email', None)

                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))
        else:
            flash('Invalid OTP code. Please try again.', 'danger')

    return render_template('otp.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template("login.html", form=form)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
