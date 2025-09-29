from db import db
from models.BaseModel import BaseModel

class User(db.Model, BaseModel):
    __tablename__ = "User"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=True)
    salt = db.Column(db.String(64), nullable=False)
    private_key = db.Column(db.String, nullable=False)
    public_key = db.Column(db.String, nullable=False)
    client_public_key = db.Column(db.String, nullable=True)
    db_username = db.Column(db.String(255), nullable=True)
    db_password = db.Column(db.String(255), nullable=True)
