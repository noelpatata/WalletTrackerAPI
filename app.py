from model.ExpenseModel import expense_bp 
from model.ExpenseCategoryModel import expensecategory_bp 
from model.Authentication import auth_bp
from flask import Flask
from dataBase.db import db
from strings import Strings

app = Flask(__name__)

app.config['PRIVATE_KEY'] = open('private_key.pem', 'r').read()
app.config['PUBLIC_KEY'] = open('public_key.pem', 'r').read()

connectionString = f'mysql://{Strings.mysqlUsername}:{Strings.mysqlPassword}@{Strings.mysqlHost}/{Strings.mysqlDbName}'
app.config['SQLALCHEMY_DATABASE_URI'] = connectionString
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)

app.register_blueprint(auth_bp)
app.register_blueprint(expense_bp)
app.register_blueprint(expensecategory_bp)

    