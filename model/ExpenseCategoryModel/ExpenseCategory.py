from dataBase.db import db
from model.BaseClass import BaseClass

class ExpenseCategory(db.Model, BaseClass):
    __tablename__ = 'ExpenseCategory'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    user = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    
    @classmethod
    def getByUser(cls, userId):
        return cls.query.filter(cls.user == userId).all()