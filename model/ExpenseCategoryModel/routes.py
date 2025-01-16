from __future__ import print_function # In python 2.7
import sys
from flask import jsonify, request
from . import expensecategory_bp
from .ExpenseCategory import ExpenseCategory
from model.ExpenseModel.Expense import Expense
from ..Authentication.routes import token_required

@expensecategory_bp.route('/ExpenseCategory/Id', methods=['GET']) #query parameter userId
@token_required
def get_by_id():
    userId = request.args.get('catId')
    categories = ExpenseCategory.getById(userId)
    for category in categories:
        total = Expense.getTotalByCategory(category.id)
        category.setTotal(total) 
    
    cat_json = [category.serialize() for category in categories]
    return jsonify(cat_json)

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

@expensecategory_bp.route('/ExpenseCategory/', methods=['POST'])  # query parameter userId
@token_required
def create_expense_category():
    try:
        #data extraction
        user_id = request.args.get('userId')
        data = request.get_json()
        
        name = data.get('name')

        #validation
        if not name or not user_id:
            return jsonify({'error': 'Invalid data'}), 500    

        #save data
        new_category = ExpenseCategory(name=name, user=user_id)
        new_category.save()
        return jsonify(new_category.serialize()), 201

    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500