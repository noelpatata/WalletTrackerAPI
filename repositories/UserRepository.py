import os, hashlib, binascii
from db import db
from models.User import User

class UserRepository:
    
    @staticmethod
    def get_by_id(user_id):
        return User.query.get(user_id)

    @staticmethod
    def get_by_username(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def exists(username) -> bool:
        return db.session.query(User.id).filter_by(username=username).first() is not None

    @staticmethod
    def create_with_password(user, password):
        """Factory: creates user with hashed password."""
        salt = os.urandom(32)
        hashed_password = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 100000
        )

        user.password = binascii.hexlify(hashed_password).decode('utf-8') 
        user.salt = binascii.hexlify(salt).decode("utf-8")
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def check_password(user: User, password: str) -> bool:
        """Verify password against stored hash."""
        salt = binascii.unhexlify(user.salt.encode("utf-8"))
        hashed_password = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, 100000
        )
        return user.password == binascii.hexlify(hashed_password).decode("utf-8")
