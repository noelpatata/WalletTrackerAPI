from db import db
from models.BaseModel import BaseModel

class Season(db.Model, BaseModel):
    __tablename__ = 'Season'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    year = db.Column(db.Integer, nullable=False)
    month = db.Column(db.Integer, nullable=False)

    __table_args__ = (
        db.UniqueConstraint('year', 'month', name='uq_season_year_month'),
    )
