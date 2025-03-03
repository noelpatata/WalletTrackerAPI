import sys
from flask import jsonify, request
from . import expense_bp
from .Expense import Expense
from ..Authentication.routes import encrypt_and_sign_data


# Endpoints
@expense_bp.route('/Expense/Id', methods=['POST']) #query parameter userId, catId
@encrypt_and_sign_data
def get_by_id(userId, decrypted_data):
    data = decrypted_data
    if not data:
        return jsonify({'error': 'Expense not provided'}), 403
    expenseId = data.get('expenseId')
    if not expenseId:
        return jsonify({'error': 'Expense not provided'}), 403
    expense = Expense.get_by_id(expenseId)
    if not expense:
        return jsonify({'success': False, 'message': 'Expense not provided'}), 403    
    expense_json = expense.serialize()
    return jsonify(expense_json)

@expense_bp.route('/Expense/CatId/', methods=['POST']) #query parameter userId, catId
@encrypt_and_sign_data
def get_by_category(userId, decrypted_data):
    data = decrypted_data
    if not data:
        return jsonify({'error': 'Data not provided'}), 403
    catId = data.get('catId')
    if not catId:
        return jsonify({'error': 'Category not provided'}), 403
    expenses = Expense.getByCategory(catId)  
    expenses_json = [expense.serialize() for expense in expenses]
    return jsonify(expenses_json)

@expense_bp.route('/Expense/create/', methods=['POST'])  # query parameter userId
@encrypt_and_sign_data
def create_expense(userId, decrypted_data):
    try:
        #data extraction
        data = decrypted_data
        if not data:
            return jsonify({'success': False, 'message': 'Invalid data'}), 403    
        userId = data.get('user')  
        price = data.get('price')
        expenseDate = data.get('expenseDate')
        catId = data.get('category')  

        #validation
        if not price or not expenseDate or not catId or not userId:
            return jsonify({'success': False, 'message': 'Bad request'}), 403    
        
        #save data
        new_expense = Expense(price=price, category = catId, user=userId, expenseDate = expenseDate)
        new_expense.save()
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'message':  f'An error occurred: {str(e)}'}), 403
    
@expense_bp.route('/Expense/all/', methods=['DELETE'])
@encrypt_and_sign_data
def delete_all(userId, decrypted_data):
    if not userId:
        return jsonify({'success': False, 'message':  'User not provided'}), 403
    try:
        Expense.deleteByUser(userId)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message':  str(e)}), 403
    
@expense_bp.route('/Expense/delete/', methods=['POST'])
@encrypt_and_sign_data
def delete_by_id(userId, decrypted_data):
    data = decrypted_data
    if not data:
        return jsonify({'error': 'Category not provided'}), 403
    expenseId = data.get('expenseId')
    if not expenseId:
        return jsonify({'success': False, 'message':  'ExpenseId not provided'}), 403
    try:
        Expense.deleteById(expenseId)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message':  str(e)}), 403
    
@expense_bp.route('/Expense/edit/', methods=['POST'])
@encrypt_and_sign_data
def edit(userId, decrypted_data):
    try:
        data = decrypted_data

        if not data:
            return jsonify({'success': False, 'message':  'Expense not provided'}), 403    
        id = data.get('id')
        exp = Expense.get_by_id(id)
        if not exp:
            return jsonify({'success': False, 'message':  'Expense not found'}), 403    
        
        exp.edit(**data)
        
        expense_json = exp.serialize()
        return jsonify(expense_json)

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 403