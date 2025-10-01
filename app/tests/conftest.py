import pytest
from app import create_app, db
from models.User import User
import os
from utils.Cryptography import hash_password

@pytest.fixture
def app():
    test_config = {
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "TESTING": True
    }
    app = create_app(test_config)
    
    with app.app_context():
        db.create_all()
        
        private_key = open("private_key.pem", "r").read()
        public_key = open("public_key.pem", "r").read()
        hex_hashed_password, hex_salt = hash_password("password123")
        test_user = User(
            username="testuser",
            password=hex_hashed_password,
            salt = hex_salt,
            private_key=private_key,
            public_key=public_key
        )
        db.session.add(test_user)
        db.session.commit()

        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()
