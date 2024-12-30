from expenses import expenses_bp
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://noel:P@ssw0rd@localhost/WalletTracker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

SQLAlchemy(app)

app.register_blueprint(expenses_bp)

if __name__ == '__main__':
    app.run(port=5000)
    