from dataBase.db import db
from model.BaseClass import BaseClass

class Expense(db.Model, BaseClass):
    __tablename__ = 'Expense'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    price = db.Column(db.Float, nullable=False)
    expenseDate = db.Column(db.Date, nullable=False)
    category = db.Column(db.Integer, db.ForeignKey('ExpenseCategory._id'), nullable=False)
    
    @classmethod
    def getByCategory(cls, catId):
        return cls.query.filter(cls.category == catId).all()