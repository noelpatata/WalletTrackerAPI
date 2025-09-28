from db import db
from repositories.BaseRepository import BaseRepository

class Expense(db.Model, BaseRepository):
    __tablename__ = 'Expense'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    price = db.Column(db.Float, nullable=False)
    expenseDate = db.Column(db.Date, nullable=False)
    category = db.Column(db.Integer, db.ForeignKey('ExpenseCategory.id'), nullable=False)
    description = db.Column(db.String(255), nullable=True)