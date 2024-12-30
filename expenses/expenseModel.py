from dataBase.db import db

class Expense(db.Model):
    __tablename__ = 'Expense'

    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    price = db.Column(db.Float, nullable=False)
    expenseDate = db.Column(db.Date, nullable=False)
    category = db.Column(db.Integer, db.ForeignKey('ExpenseCategory._id'), nullable=False)