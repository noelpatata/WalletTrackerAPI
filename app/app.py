import os
from flask import Flask
from endpoints.ExpenseEndpoints import expense_bp 
from endpoints.ExpenseCategoryEndpoints import expensecategory_bp 
from endpoints.AuthenticationEndpoints import auth_bp
from db import db
from config import MYSQLUSERNAME, MYSQLPASSWORD, MYSQLHOST, MYSQLDBNAME
from utils.Cryptography import generate_keys_file
from utils.Logger import AppLogger

def create_app_test(test_config=None):
    app = Flask(__name__)

    app.config.update(test_config)
    AppLogger.configure()

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(expense_bp)
    app.register_blueprint(expensecategory_bp)

    return app

def create_app():

    app = Flask(__name__)
    AppLogger.configure("app.log")

    if not (os.path.exists("private_key.pem") and os.path.exists("public_key.pem")):
    generate_keys_file()
        
    app.config['PRIVATE_KEY'] = open('private_key.pem', 'r').read()
    app.config['PUBLIC_KEY'] = open('public_key.pem', 'r').read()
    connectionString = f'mysql://{MYSQLUSERNAME}:{MYSQLPASSWORD}@{MYSQLHOST}/{MYSQLDBNAME}'
    app.config['SQLALCHEMY_DATABASE_URI'] = connectionString   

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(expense_bp)
    app.register_blueprint(expensecategory_bp)

    return app


    