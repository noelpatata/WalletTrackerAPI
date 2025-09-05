from sqlalchemy import func
from db import db
from BaseRepository import BaseRepository

class ExpenseCategory(db.Model, BaseRepository):
    __tablename__ = 'ExpenseCategory'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    sortOrder = db.Column(db.Integer, nullable=True)
    total = 0
    
    def setTotal(self, total):
        self.total = total
    
    def serialize(self):
        result = super().serialize()
        
        result['total'] = self.total
        
        return result
    
    def editName(self, new_name):
        if hasattr(self, 'name'):
            self.name = new_name
            self.save()
    
    @classmethod
    def getById(cls, expense_id):
        return cls.query.filter(cls.id == expense_id).first()
    
    @classmethod
    def deleteById(cls, expense_id):
        cls.query.filter(cls.id == expense_id).delete()
        db.session.commit()
        
    @classmethod
    def getAll(cls):
        expense_categories = cls.query.order_by(
            func.coalesce(cls.sortOrder, 0),
            cls.sortOrder.asc(),
            cls.id
        ).all()
        
        return expense_categories