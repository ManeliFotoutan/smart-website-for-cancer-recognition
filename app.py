from flask import Flask, render_template, redirect, url_for, request, session,flash
from flask_sqlalchemy import SQLAlchemy # for database
from flask_wtf import FlaskForm # for input data
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Regexp
from flask_wtf.csrf import CSRFProtect
import os


app = Flask(__name__)
# CSRF Token
csrf = CSRFProtect(app)

# create database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# create tabel
class users(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), nullable = False, unique = True)
    password = db.Column(db.String(128), nullable = False)



# create database
with app.app_context():
    db.create_all()

# regester page
class userForm(FlaskForm):
    username = StringField(label="username",validators=[
        DataRequired(),
        Regexp(
            regex="^[a-zA-Z0-9_]{3,10}$",
            message="Username must be between 3 and 10 characters and can only contain letters, numbers, and underscores."
        )])
    password = PasswordField(label="password",validators=[DataRequired()])
    submit = SubmitField(label='submit')

@app.route("/regester", methods = ['GET', "POST"])
def regester():
    form = userForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        newUser = users(
            username = username,
            password = password
        )
        db.session.add(newUser)
        db.session.commit()

        return redirect(url_for("login"))
    
    return render_template("regester.html", form=form)



@app.route("/login", methods = ["GET", "POST"])
def login():
    form = userForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # validate in database
        user = users.query.filter_by(username=username).first()

        if user and password:
            session['username'] = user.username

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/our-team')
def our_team():
    return render_template('our-team.html')

secert_key = os.urandom(12)
app.config['SECRET_KEY'] = secert_key
if __name__ == '__main__':
    app.run(debug=True, port=5001)
