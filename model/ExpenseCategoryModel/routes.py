from __future__ import print_function # In python 2.7
import sys
from flask import jsonify, request
from . import expensecategory_bp
from .ExpenseCategory import ExpenseCategory
from model.ExpenseModel.Expense import Expense
from ..Authentication.routes import token_required

@expensecategory_bp.route('/ExpenseCategory/Id/', methods=['GET']) #query parameter userId
@token_required
def get_by_id(userId):
    try:
        catId = request.args.get('catId')
        category = ExpenseCategory.getById(catId)
        total = Expense.getTotalByCategory(category.id)
        category.setTotal(total) 
        return jsonify(category.serialize())
    except Exception as e:
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 203
    

@expensecategory_bp.route('/ExpenseCategory/', methods=['GET']) #query parameter userId
@token_required
def get_by_user(userId):
    try:
        if not userId:
            return jsonify({'success': False, 'message':  'User not provided'}), 203
        categories = ExpenseCategory.getByUser(userId)
        for category in categories:
            total = Expense.getTotalByCategory(category.id)
            category.setTotal(total) 
        cat_json = [category.serialize() for category in categories]
        return jsonify(cat_json)
    except Exception as e:
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 203
    

@expensecategory_bp.route('/ExpenseCategory/', methods=['POST'])  # query parameter userId
@token_required
def create_expense_category(userId):
    try:
        #data extraction
        data = request.get_json()
        
        name = data.get('name')

        #validation
        if not name or not userId:
            return jsonify({'success': False, 'message': 'Invalid data'}), 203    

        #save data
        new_category = ExpenseCategory(name=name, user=userId)
        new_category.save()
        return jsonify(new_category.serialize()), 201

    except Exception as e:
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 203
@expensecategory_bp.route('/ExpenseCategory/', methods=['DELETE'])
@token_required
def delete_by_id(userId):
    try:
        catId = request.args.get('catId')

        if not catId:
            return jsonify({'success': False, 'message': 'CategoryId not provided'}), 203    

        ExpenseCategory.deleteById(catId)
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 203
    
@expensecategory_bp.route('/ExpenseCategory/editName', methods=['POST'])
@token_required
def edit_name(userId):
    try:
        data = request.get_json()

        if not data:
            return jsonify({'success': False, 'message': 'Category not provided'}), 203    
        
        cat = ExpenseCategory.getById(data.get('id'))
        cat.editName(data.get('name'))
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 203