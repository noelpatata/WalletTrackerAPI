from datetime import datetime
from db import db
from models.BaseModel import BaseModel

class RefreshToken(db.Model, BaseModel):
    __tablename__ = "RefreshToken"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    def is_valid(self):
        return not self.revoked and self.expires_at > datetime.utcnow()
