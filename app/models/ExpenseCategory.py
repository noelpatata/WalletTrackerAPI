from db import db
from models.BaseModel import BaseModel

class ExpenseCategory(db.Model, BaseModel):
    __tablename__ = 'ExpenseCategory'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    sortOrder = db.Column(db.Integer, nullable=True)
    total = 0  

    def setTotal(self, total):
        self.total = total
        
    def setName(self, name):
        self.name = name

    def to_json_dict(self):
        result = super().to_json_dict()
        result['total'] = self.total
        return result
