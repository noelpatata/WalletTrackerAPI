from dataBase.db import db
from model.BaseClass import BaseClass

class ExpenseCategory(db.Model, BaseClass):
    __tablename__ = 'ExpenseCategory'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String, nullable=False)
    user = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    total = 0
    
    def setTotal(self, total):
        self.total = total
    
    def serialize(self):
        result = super().serialize()
        
        result['total'] = self.total #custom serialization
        
        return result
    
    def editName(self, new_name):
        if hasattr(self, 'name'):
            self.name = new_name
            self.save()

    @classmethod
    def getByUser(cls, userId):
        return cls.query.filter(cls.user == userId).all()
    
    @classmethod
    def getById(cls, userId):
        return cls.query.filter(cls.id == userId).first()
    
    @classmethod
    def deleteById(cls, catId):
        cls.query.filter(cls.id == catId).delete()
        db.session.commit()
        
    @classmethod
    def getAllByUserId(cls, userId):
        cls.query.filter(cls.user == userId).all()
        db.session.commit()