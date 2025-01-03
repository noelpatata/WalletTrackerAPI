from model.ExpenseModel import expense_bp 
from model.Authentication import auth_bp
from flask import Flask
from dataBase.db import db
from strings import Strings

app = Flask(__name__)

app.config['secret_key'] = Strings.secretKey

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:?!tr3n3s!?@localhost/WalletTracker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)

app.register_blueprint(auth_bp)
app.register_blueprint(expense_bp)

    