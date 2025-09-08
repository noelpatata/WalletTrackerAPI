from datetime import date
from db import db

class BaseRepository:

    def save(self, session=None):
        if session is None:
            session = db.session
        session.add(self)
        session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def toJsonDict(self):
        result = {}
        for column in self.__table__.columns:
            
            value = getattr(self, column.name)
            if isinstance(value, date):
                value = value.isoformat()
            result[column.name] = value
        return result
    
    def edit(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                if key != "id" and key != "username":
                    setattr(self, key, value)
        self.save()
        
    @classmethod
    def getAll(cls):
        return cls.query.all()

    @classmethod
    def getById(cls, id):
        return cls.query.get(id)

    @classmethod
    def simple_filter(cls, **kwargs):
        return cls.query.filter_by(**kwargs).all()
    
    @classmethod
    def rollback(cls):
        cls.session.rollback()
    
    @classmethod
    def deleteAll(cls):
        cls.query.delete()
        cls.query.session.commit()