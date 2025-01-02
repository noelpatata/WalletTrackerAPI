from sqlalchemy import Date
from flask_sqlalchemy import SQLAlchemy
from dataBase import db



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
            if isinstance(value, Date):  # Handle Date fields
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