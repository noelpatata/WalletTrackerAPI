from model.ExpenseModel import expenses_bp
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dataBase.db import db

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:?!tr3n3s!?@localhost/WalletTracker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

app.register_blueprint(expenses_bp)

if __name__ == '__main__':
    app.run(port=5000, debug=True)
    