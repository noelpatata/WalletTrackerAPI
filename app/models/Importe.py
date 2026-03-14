from db import db
from models.BaseModel import BaseModel

class Importe(db.Model, BaseModel):
    __tablename__ = 'Importe'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    concept = db.Column(db.String(255), nullable=True)
    importeDate = db.Column(db.Date, nullable=False)
    amount = db.Column(db.Float, nullable=False)
    balanceAfter = db.Column(db.Float, nullable=True)
    iban = db.Column(db.String(64), nullable=True)
    seasonId = db.Column(db.Integer, db.ForeignKey('Season.id', ondelete='CASCADE'), nullable=False)
