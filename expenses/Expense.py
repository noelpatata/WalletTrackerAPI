from dataBase.db import db
from baseClass import BaseClass

class Expense(db.Model, BaseClass):
    __tablename__ = 'Expense'

    _id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    price = db.Column(db.Float, nullable=False)
    expenseDate = db.Column(db.Date, nullable=False)
    category = db.Column(db.Integer, db.ForeignKey('ExpenseCategory._id'), nullable=False)
    
    @classmethod
    def getByCategory(cls, catid):
        return cls.query.filter(cls.category == catid).all()
    
    def to_dict(self):
        return {
            'id': self._id,
            'price': self.price,
            'expenseDate': self.expenseDate.isoformat(),  # Convert Date to ISO format string
            'category': self.category,
        }