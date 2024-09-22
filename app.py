from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Regexp, Length
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps


app = Flask(__name__)
# CSRF Token
csrf = CSRFProtect(app)

# create database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(12)

db = SQLAlchemy(app)

# create tabel
class Users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), nullable = False, unique = True)
    password = db.Column(db.String(128), nullable = False)


# create database
with app.app_context():
    db.create_all()

# Registration form
class UserForm(FlaskForm):
    username = StringField(label="Username", validators=[
        DataRequired(),
        Regexp(
            regex="^[a-zA-Z0-9_]{3,10}$",
            message="Username must be between 3 and 10 characters and can only contain letters, numbers, and underscores."
        )])
    password = PasswordField(label="Password", validators=[
        DataRequired(),
        Length(min=6, message="Password must be at least 6 characters long.")
    ])
    submit = SubmitField(label='Submit')

# Decorator to restrict access to logged-in users
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You need to be logged in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Registration route
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = UserForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user_exists = Users.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already taken, please choose another one.', 'warning')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = Users(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template("register.html", form=form)

# Login route
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = UserForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = Users.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template("login.html", form=form)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/our-team')
def our_team():
    return render_template('our-team.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    session.clear() 
    flash('You have been logged out.', 'success')  
    return redirect(url_for('login'))


secert_key = os.urandom(12)
app.config['SECRET_KEY'] = secert_key

if __name__ == '__main__':
    app.run(debug=True, port=5001)
