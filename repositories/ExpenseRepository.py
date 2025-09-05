from sqlalchemy import desc
from db import db
from BaseRepository import BaseRepository

class Expense(db.Model, BaseRepository):
    __tablename__ = 'Expense'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    price = db.Column(db.Float, nullable=False)
    expenseDate = db.Column(db.Date, nullable=False)
    category = db.Column(db.Integer, db.ForeignKey('ExpenseCategory.id'), nullable=False)
    
    @classmethod
    def getByCategory(cls, category_id):
        return cls.query.filter(cls.category == category_id).order_by(
            desc(cls.expenseDate),
            desc(cls.id)
        ).all()
    
    @classmethod
    def getTotalByCategory(cls, category_id):
        total = db.session.query(db.func.sum(cls.price)).filter(cls.category == category_id).scalar()
        return total or 0.0
    
    @classmethod
    def deleteAll(cls):
        cls.query.delete()
        db.session.commit()
    
    @classmethod
    def deleteById(cls, expense_id):
        cls.query.filter(cls.id == expense_id).delete()
        db.session.commit()
        