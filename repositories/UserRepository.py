from db import db
import hashlib
import os
import binascii
from BaseRepository import BaseRepository

class User(db.Model, BaseRepository):
    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=True)
    salt = db.Column(db.String, nullable=False)
    private_key = db.Column(db.String, nullable=False)
    public_key = db.Column(db.String, nullable=False)
    client_public_key = db.Column(db.String, nullable=False)
    db_username = db.Column(db.String(255), nullable=False)
    db_password = db.Column(db.String(255), nullable=False)
    
    @classmethod
    def check_exists(cls, username):
        userFromQuery = cls.query.filter(cls.username == username).first()
        return userFromQuery != None

    def set_password(self, password):
        salt = os.urandom(32)  # Generate a 16-byte random salt
        self.salt = binascii.hexlify(salt).decode('utf-8')  # Store as hex
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, 100000
        )
        self.password = binascii.hexlify(hashed_password).decode('utf-8')  # Store as hex
        self.save()

    def CorrectPassword(self, password):
        """Verifies the provided password against the stored hash."""
        salt = binascii.unhexlify(self.salt.encode('utf-8'))  # Decode the stored salt
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'), salt, 100000
        )
        return self.password == binascii.hexlify(hashed_password).decode('utf-8')
    def IsCorrectPassword(self, hashed_password):
        return self.password == hashed_password
            
        
    