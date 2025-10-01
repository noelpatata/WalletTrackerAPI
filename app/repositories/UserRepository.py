import os, hashlib, binascii
from db import db
from models.User import User
from utils.Cryptography import hash_password

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
        hex_hashed_password, hex_salt = hash_password(password) 
        user.password = hex_hashed_password
        user.salt = hex_salt
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def check_password(user: User, password: str) -> bool:
        hex_hashed_password, hex_salt = hash_password(password, user.salt)
        return user.password == hex_hashed_password
