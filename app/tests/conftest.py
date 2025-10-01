import pytest
from app import create_app_test, db
from models.User import User
from utils.Cryptography import hash_password, generate_keys_file

@pytest.fixture
def keys(tmp_path):
    private_key_path = tmp_path / "private_key.pem"
    public_key_path = tmp_path / "public_key.pem"
    generate_keys_file(str(tmp_path))
    with open(private_key_path, "r") as f:
        private_key = f.read()
    with open(public_key_path, "r") as f:
        public_key = f.read()
    return {"private": private_key, "public": public_key}


@pytest.fixture
def app(keys, tmp_path):
    db_path = tmp_path / "test.db"
    test_config = {
        "PRIVATE_KEY": keys["private"],
        "PUBLIC_KEY": keys["public"],
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_path}",
        "TESTING": True,
    }

    app = create_app_test(test_config)

    with app.app_context():
        from models.User import User
        db.create_all()

        hex_hashed_password, hex_salt = hash_password("password123")
        user = User(
            username="testuser",
            password=hex_hashed_password,
            salt=hex_salt,
            private_key=keys["private"],
            public_key=keys["public"],
        )
        db.session.add(user)
        db.session.commit()

    yield app

    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
