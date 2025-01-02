from flask_sqlalchemy import SQLAlchemy
from model.BaseClass import BaseClass

db = SQLAlchemy(model_class=BaseClass)