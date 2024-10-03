from app import db
from datetime import datetime


# User model
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    result = db.relationship("userResult", backref='author', lazy = True)

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


    result = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable = False)
