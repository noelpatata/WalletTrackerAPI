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
        
    def setName(self, name):
        self.name = name

    def toJsonDict(self):
        result = super().toJsonDict()
        result['total'] = self.total
        return result
