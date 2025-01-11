from dataBase.db import db
from model.BaseClass import BaseClass

class Expense(db.Model, BaseClass):
    __tablename__ = 'Expense'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    price = db.Column(db.Float, nullable=False)
    expenseDate = db.Column(db.Date, nullable=False)
    category = db.Column(db.Integer, db.ForeignKey('ExpenseCategory._id'), nullable=False)
    user = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    
    @classmethod
    def getByCategory(cls, catId):
        return cls.query.filter(cls.category == catId).all()
    
    @classmethod
    def getTotalByCategory(cls, catId):
        total = db.session.query(db.func.sum(cls.price)).filter(cls.category == catId).scalar()
        return total or 0.0
    @classmethod
    def deleteByUser(cls, userId):
        cls.query.filter(cls.user == userId).delete()
        db.session.commit()
        