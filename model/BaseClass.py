from datetime import date
from dataBase.db import db

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
    def edit(self, **kwargs):
        """
        Edit all given attributes of the object.

        Args:
            **kwargs: Key-value pairs where keys are attribute names and values are new values.
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                if key != "id" and key != "username":
                    setattr(self, key, value)
        self.save()
        
    @classmethod
    def get_all(cls):
        return cls.query.all()

    @classmethod
    def get_by_id(cls, id):
        return cls.query.get(id)

    @classmethod
    def simple_filter(cls, **kwargs):
        return cls.query.filter_by(**kwargs).all()
    
    @classmethod
    def rollback(cls):
        cls.session.rollback()
    
    @classmethod
    def delete_all(cls):
        cls.query.delete()
        cls.query.session.commit()