import os

DATABASE_PASSWORD = os.environ.get("DATABASE_ROOT_PASSWORD", "12345678")
DATABASE_NAME = os.environ.get("DATABASE_NAME", "wallet_tracker")
DATABASE_USERNAME = os.environ.get("WALLET_TRACKER_DB_USER", "root")
DATABASE_HOST = os.environ.get("WALLET_TRACKER_DB_HOST", "db")
SECRET = os.environ.get("WALLET_TRACKER_SECRET", "randomSecret")
ENABLE_REGISTER = os.environ.get("ENABLE_REGISTER", "false")
