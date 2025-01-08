from flask import Blueprint

expense_bp = Blueprint('expense', __name__)

from . import routes
