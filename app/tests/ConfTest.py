import os
import pytest
from app import create_app, db as _db
from app.models import User, UserRepository

os.environ["MYSQL_ROOT_PASSWORD"] = os.getenv("MYSQL_ROOT_PASSWORD", "adminadmin")
os.environ["MYSQL_DATABASE"] = os.getenv("MYSQL_DATABASE", "wallet_tracker")
os.environ["WALLET_TRACKER_DB_USER"] = os.getenv("WALLET_TRACKER_DB_USER", "root")
os.environ["WALLET_TRACKER_DB_HOST"] = os.getenv("WALLET_TRACKER_DB_HOST", "db")
os.environ["WALLET_TRACKER_SECRET"] = os.getenv("WALLET_TRACKER_SECRET", "s0m3r4nd0mt3xt")


@pytest.fixture(scope="session")
def app():
    """Create and configure a new app instance for tests."""
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": os.getenv("TEST_DATABASE_URI", "sqlite:///:memory:"),
        "SECRET_KEY": os.environ["WALLET_TRACKER_SECRET"],
    })
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def init_database(app):
    """Insert test data into the database."""
    user = User(username="testuser")
    UserRepository.set_password(user, "testpass")  # assuming this hashes the password
    _db.session.add(user)
    _db.session.commit()
    yield
    _db.session.remove()
    _db.drop_all()
    _db.create_all()
