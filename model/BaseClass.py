from datetime import date
from dataBase import db
import sys



class BaseClass:

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def serialize(self):
        """Dynamically serialize the object's attributes."""
        result = {}
        for column in self.__table__.columns:
            
            value = getattr(self, column.name)
            print(type(value).__name__, file=sys.stderr)
            if isinstance(value, date):  # Handle Date fields
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