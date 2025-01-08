from flask import jsonify, request
from . import expense_bp
from .Expense import Expense
from ..Authentication.routes import token_required


# Endpoints
@expense_bp.route('/Expense/<int:catId>', methods=['GET'])
@token_required
def get_by_user(catId: int):
    expenses = Expense.getByCategory(catId)
    expenses_json = [expense.serialize() for expense in expenses]  # Assuming a `to_dict` method
    return jsonify(expenses_json)