from flask_sqlalchemy import SQLAlchemy
from baseClass import BaseClass

db = SQLAlchemy(model_class=BaseClass)