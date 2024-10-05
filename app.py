from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    session,
    flash,
    make_response,
)
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
from forms import UserForm, LoginForm, OTPForm
from OTP import send_code
from model import cancer_prediction

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config["SECRET_KEY"] = os.urandom(12)


# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
from datetime import datetime


# User model
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    result = db.relationship("userResult", backref="author", lazy=True)


class userResult(db.Model):
    __tablename__ = "user_result"
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    id = db.Column(db.Integer, primary_key=True)
    mean_radius = db.Column(db.Float, nullable=False)
    mean_texture = db.Column(db.Float, nullable=False)
    mean_perimeter = db.Column(db.Float, nullable=False)
    mean_area = db.Column(db.Float, nullable=False)
    mean_smoothness = db.Column(db.Float, nullable=False)
    mean_compactness = db.Column(db.Float, nullable=False)
    mean_concavity = db.Column(db.Float, nullable=False)
    mean_concave_points = db.Column(db.Float, nullable=False)
    mean_symmetry = db.Column(db.Float, nullable=False)
    mean_fractal_dimension = db.Column(db.Float, nullable=False)
    radius_se = db.Column(db.Float, nullable=False)
    texture_se = db.Column(db.Float, nullable=False)
    perimeter_se = db.Column(db.Float, nullable=False)
    area_se = db.Column(db.Float, nullable=False)
    smoothness_se = db.Column(db.Float, nullable=False)
    compactness_se = db.Column(db.Float, nullable=False)
    concavity_se = db.Column(db.Float, nullable=False)
    concave_points_se = db.Column(db.Float, nullable=False)
    symmetry_se = db.Column(db.Float, nullable=False)
    fractal_dimension_se = db.Column(db.Float, nullable=False)
    worst_radius = db.Column(db.Float, nullable=False)
    worst_texture = db.Column(db.Float, nullable=False)
    worst_perimeter = db.Column(db.Float, nullable=False)
    worst_area = db.Column(db.Float, nullable=False)
    worst_smoothness = db.Column(db.Float, nullable=False)
    worst_compactness = db.Column(db.Float, nullable=False)
    worst_concavity = db.Column(db.Float, nullable=False)
    worst_concave_points = db.Column(db.Float, nullable=False)
    worst_symmetry = db.Column(db.Float, nullable=False)
    worst_fractal_dimension = db.Column(db.Float, nullable=False)

    result = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            flash("You need to be logged in to access this page.", "danger")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/our-team")
def our_team():
    return render_template("our-team.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        if User.query.filter_by(username=username).first():
            flash("Username already taken, please choose another one.", "warning")
            return redirect(url_for("register"))

        session["username"] = username
        session["email"] = email
        session["password"] = password
        otp_code = send_code(email)
        resp = make_response(redirect(url_for("otp")))
        resp.set_cookie("otp_code", str(otp_code))
        return resp

    return render_template("register.html", form=form)


# OTP validation function
def otp_code_isvalid(code):
    encrypted_otp_code = request.cookies.get("otp_code")
    return encrypted_otp_code and int(encrypted_otp_code) == code


@app.route("/otp", methods=["GET", "POST"])
def otp():
    form = OTPForm()
    if form.validate_on_submit():
        code = int(f"{form.otp1.data}{form.otp2.data}{form.otp3.data}{form.otp4.data}")

        if otp_code_isvalid(code):
            username = session.get("username")
            email = session.get("email")
            password = session.get("password")

            if username and password and email:
                hashed_password = generate_password_hash(password)
                new_user = User(username=username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()

                session.pop("username", None)
                session.pop("password", None)
                session.pop("email", None)

                flash("Registration successful! You can now log in.", "success")
                return redirect(url_for("login"))
        else:
            flash("Invalid OTP code. Please try again.", "danger")

    return render_template("otp.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session["username"] = user.username
            flash("Login successful!", "success")
            return redirect(url_for("input"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/input", methods=["GET", "POST"])
@login_required
def input():
    current_user = User.query.filter_by(username=session["username"]).first()
    if request.method == "POST":
        mean_radius = float(request.form["mean_radius"])
        mean_texture = float(request.form["mean_texture"])
        mean_perimeter = float(request.form["mean_perimeter"])
        mean_area = float(request.form["mean_area"])
        mean_smoothness = float(request.form["mean_smoothness"])
        mean_compactness = float(request.form["mean_compactness"])
        mean_concavity = float(request.form["mean_concavity"])
        mean_concave_points = float(request.form["mean_concave_points"])
        mean_symmetry = float(request.form["mean_symmetry"])
        mean_fractal_dimension = float(request.form["mean_fractal_dimension"])
        radius_se = float(request.form["radius_se"])
        texture_se = float(request.form["texture_se"])
        perimeter_se = float(request.form["perimeter_se"])
        area_se = float(request.form["area_se"])
        smoothness_se = float(request.form["smoothness_se"])
        compactness_se = float(request.form["compactness_se"])
        concavity_se = float(request.form["concavity_se"])
        concave_points_se = float(request.form["concave_points_se"])
        symmetry_se = float(request.form["symmetry_se"])
        fractal_dimension_se = float(request.form["fractal_dimension_se"])
        worst_radius = float(request.form["worst_radius"])
        worst_texture = float(request.form["worst_texture"])
        worst_perimeter = float(request.form["worst_perimeter"])
        worst_area = float(request.form["worst_area"])
        worst_smoothness = float(request.form["worst_smoothness"])
        worst_compactness = float(request.form["worst_compactness"])
        worst_concavity = float(request.form["worst_concavity"])
        worst_concave_points = float(request.form["worst_concave_points"])
        worst_symmetry = float(request.form["worst_symmetry"])
        worst_fractal_dimension = float(request.form["worst_fractal_dimension"])

        features = [
            mean_radius,
            mean_texture,
            mean_perimeter,
            mean_area,
            mean_smoothness,
            mean_compactness,
            mean_concavity,
            mean_concave_points,
            mean_symmetry,
            mean_fractal_dimension,
            radius_se,
            texture_se,
            perimeter_se,
            area_se,
            smoothness_se,
            compactness_se,
            concavity_se,
            concave_points_se,
            symmetry_se,
            fractal_dimension_se,
            worst_radius,
            worst_texture,
            worst_perimeter,
            worst_area,
            worst_smoothness,
            worst_compactness,
            worst_concavity,
            worst_concave_points,
            worst_symmetry,
            worst_fractal_dimension,
        ]

        prediction = cancer_prediction(features)

        # Create a new record in the userResult table with all the inputs
        new_result = userResult(
            mean_radius=mean_radius,
            mean_texture=mean_texture,
            mean_perimeter=mean_perimeter,
            mean_area=mean_area,
            mean_smoothness=mean_smoothness,
            mean_compactness=mean_compactness,
            mean_concavity=mean_concavity,
            mean_concave_points=mean_concave_points,
            mean_symmetry=mean_symmetry,
            mean_fractal_dimension=mean_fractal_dimension,
            radius_se=radius_se,
            texture_se=texture_se,
            perimeter_se=perimeter_se,
            area_se=area_se,
            smoothness_se=smoothness_se,
            compactness_se=compactness_se,
            concavity_se=concavity_se,
            concave_points_se=concave_points_se,
            symmetry_se=symmetry_se,
            fractal_dimension_se=fractal_dimension_se,
            worst_radius=worst_radius,
            worst_texture=worst_texture,
            worst_perimeter=worst_perimeter,
            worst_area=worst_area,
            worst_smoothness=worst_smoothness,
            worst_compactness=worst_compactness,
            worst_concavity=worst_concavity,
            worst_concave_points=worst_concave_points,
            worst_symmetry=worst_symmetry,
            worst_fractal_dimension=worst_fractal_dimension,
            result=prediction,
            user_id=current_user.id,
        )
        db.session.add(new_result)
        db.session.commit()

        return render_template("result.html", prediction=prediction)

    return render_template("input.html")


@app.route("/history")
@login_required
def history():
    current_user = User.query.filter_by(username=session["username"]).first()

    # all previous predictions for the logged-in user
    predictions = userResult.query.filter_by(user_id=current_user.id).all()

    return render_template("history.html", predictions=predictions)


@app.route("/result")
@login_required
def result():
    current_user = User.query.filter_by(username=session["username"]).first()
    prediction = (
        db.session.query(userResult.result).filter_by(id=current_user.id).first()[0]
    )

    return render_template("result.html", prediction=prediction)


if __name__ == "__main__":
    # Create database
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)
