from sqlalchemy import func
from db import db
from repositories.BaseRepository import BaseRepository

class ExpenseCategory(db.Model, BaseRepository):
    __tablename__ = 'ExpenseCategory'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
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
    def getById(cls, expense_id, session=None):
        sess = session or db.session
        row = sess.query(cls).filter(cls.id == expense_id).first()
        return row

    @classmethod
    def getAll(cls, session=None):
        sess = session or db.session
        rows = sess.query(cls).order_by(
            func.coalesce(cls.sortOrder, 0),
            cls.sortOrder.asc(),
            cls.id
        ).all()
        return rows