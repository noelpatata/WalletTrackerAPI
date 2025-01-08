from flask import Blueprint

expensecategory_bp = Blueprint('expensecategory', __name__)

from . import routes
