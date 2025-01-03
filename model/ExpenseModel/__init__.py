from flask import Blueprint

expense_bp = Blueprint('expenses', __name__)

from . import routes
