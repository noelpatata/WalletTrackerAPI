from __future__ import print_function # In python 2.7
import sys
from flask import jsonify, request
from . import expensecategory_bp
from .ExpenseCategory import ExpenseCategory
from model.ExpenseModel.Expense import Expense
from ..Authentication.routes import token_required


@expensecategory_bp.route('/ExpenseCategory/', methods=['GET']) #query parameter userId
@token_required
def get_by_user():
    userId = request.args.get('userId')
    categories = ExpenseCategory.getByUser(userId)
    for category in categories:
        total = Expense.getTotalByCategory(category.id)
        category.setTotal(total) 
    
    cat_json = [category.serialize() for category in categories]
    return jsonify(cat_json)