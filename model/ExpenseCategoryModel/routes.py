from flask import jsonify, request
from . import expensecategory_bp
from .ExpenseCategory import ExpenseCategory
from ..Authentication.routes import ExpenseCategoryToken_required


# Endpoints
@expensecategory_bp.route('/ExpenseCategory/<int:userId>', methods=['GET'])
@ExpenseCategoryToken_required
def get_by_user(userId: int):
    categories = ExpenseCategory.getByUser(userId)
    cat_json = [category.serialize() for category in categories]  # Assuming a `to_dict` method
    return jsonify(cat_json)