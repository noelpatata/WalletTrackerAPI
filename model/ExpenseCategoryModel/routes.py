from flask import jsonify, request
from . import expensecategory_bp
from .ExpenseCategory import ExpenseCategory
from ..Authentication.routes import token_required


@expensecategory_bp.route('/ExpenseCategory/', methods=['GET']) #query parameter userId
@token_required
def get_by_user():
    userId = request.args.get('userId')
    categories = ExpenseCategory.getByUser(userId)
    cat_json = [category.serialize() for category in categories]
    return jsonify(cat_json)