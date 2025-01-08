from flask import jsonify, request
from . import expense_bp
from .Expense import Expense
from ..Authentication.routes import token_required


# Endpoints
@expense_bp.route('/Expense/', methods=['GET']) #query parameter userId, catId
@token_required
def get_by_category():
    catId = request.args.get('catId')
    if not catId:
        return jsonify({'error': 'Category not provided'}), 403
    expenses = Expense.getByCategory(catId)
    expenses_json = [expense.serialize() for expense in expenses]
    return jsonify(expenses_json)

@expense_bp.route('/Expense/total/', methods=['GET'])  # query parameter catId
@token_required
def get_total_by_category():
    catId = request.args.get('catId')
    if not catId:
        return jsonify({'error': 'Category not provided'}), 403

    try:
        # Assuming Expense has a method to calculate the total by category
        total = Expense.getTotalByCategory(catId)
        return jsonify({'total': total}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# insert Expense

# delete Expense

# update Expense