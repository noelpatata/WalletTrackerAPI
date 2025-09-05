from endpoints.ExpenseEndpoints import expense_bp 
from endpoints.ExpenseCatogoryEndpoints import expensecategory_bp 
from endpoints.AuthenticationEndpoints import auth_bp
from flask import Flask
from db import db
from config import MYSQLUSERNAME, MYSQLPASSWORD, MYSQLHOST, MYSQLDBNAME

app = Flask(__name__)

app.config['PRIVATE_KEY'] = open('private_key.pem', 'r').read()
app.config['PUBLIC_KEY'] = open('public_key.pem', 'r').read()

connectionString = f'mysql://{MYSQLUSERNAME}:{MYSQLPASSWORD}@{MYSQLHOST}/{MYSQLDBNAME}'
app.config['SQLALCHEMY_DATABASE_URI'] = connectionString
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)

app.register_blueprint(auth_bp)
app.register_blueprint(expense_bp)
app.register_blueprint(expensecategory_bp)

    