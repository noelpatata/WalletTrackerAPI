from model.ExpenseModel import expense_bp 
from model.Authentication import auth_bp
from flask import Flask
from dataBase.db import db
from strings import Strings

app = Flask(__name__)

app.config['PRIVATE_KEY'] = open('private_key.pem', 'r').read()
app.config['PUBLIC_KEY'] = open('public_key.pem', 'r').read()

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://root:{Strings.mysqlPassword}@localhost/WalletTracker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['debug']=True


db.init_app(app)

app.register_blueprint(auth_bp)
app.register_blueprint(expense_bp)

    