from datetime import date
from dataBase.db import db
import sys



class BaseClass:

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def serialize(self):
        result = {}
        for column in self.__table__.columns:
            
            value = getattr(self, column.name)
            if isinstance(value, date):
                value = value.isoformat()
            result[column.name] = value
        return result

    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get(id)

    @classmethod
    def simple_filter(cls, **kwargs):
        return cls.query.filter_by(**kwargs).all()