import os
from flask import Flask
from endpoints.ExpenseEndpoints import expense_bp 
from endpoints.ExpenseCategoryEndpoints import expensecategory_bp 
from endpoints.AuthenticationEndpoints import auth_bp
from endpoints.HealthEndpoints import health_bp
from db import db
from config import MYSQLUSERNAME, MYSQLPASSWORD, MYSQLHOST, ENABLE_REGISTER
from utils.Cryptography import generate_keys_file
from utils.Logger import AppLogger

def create_app_test(test_config=None):
    app = Flask(__name__)

    app.config.update(test_config)

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['ENABLE_REGISTER'] = True
    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(expense_bp)
    app.register_blueprint(expensecategory_bp)
    app.register_blueprint(health_bp)

    return app

def create_app():

    app = Flask(__name__)
    log_path = os.path.join(os.path.dirname(__file__), "logs", "app.log")
    AppLogger.configure(log_path)

    if not (os.path.exists("private_key.pem") and os.path.exists("public_key.pem")):
        generate_keys_file()
    
    enable_register = ENABLE_REGISTER.lower() == "true"
    app.config['ENABLE_REGISTER'] = enable_register
    app.config['PRIVATE_KEY'] = open('private_key.pem', 'r').read()
    app.config['PUBLIC_KEY'] = open('public_key.pem', 'r').read()
    connectionString = f'mysql://{MYSQLUSERNAME}:{MYSQLPASSWORD}@{MYSQLHOST}/{MYSQLDBNAME}'
    app.config['SQLALCHEMY_DATABASE_URI'] = connectionString   

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(expense_bp)
    app.register_blueprint(expensecategory_bp)
    app.register_blueprint(health_bp)

    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.error("Unhandled exception:\n%s", traceback.format_exc())
        from utils.Constants import Messages
        from utils.ResponseMaker import make_response
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

    return app

    return app


    