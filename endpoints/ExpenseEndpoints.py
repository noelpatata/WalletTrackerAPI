from flask import Blueprint, jsonify
from repositories.ExpenseRepository import ExpenseRepository
from endpoints.middlewares.auth_middleware import cryptography_required
from utils.responseMaker import make_response
from utils.constants import Messages, AuthMessages, ExpenseMessages

expense_bp = Blueprint('expense', __name__)

@expense_bp.route('/Expense', methods=['GET'])
@cryptography_required
def get_by_id(userId, session, user, decrypted_data):
    try:
        data = decrypted_data
        
        expenseId = data.get('expenseId')
        if not expenseId:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200

        expense = ExpenseRepository.get_by_id(expenseId, session)
        if not expense:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        return make_response(expense, True, ExpenseMessages.FETCHED)
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
    

@expense_bp.route('/Expense/catId/', methods=['GET'])
@cryptography_required
def get_by_category(userId, decrypted_data):
    data = decrypted_data
    if not data:
        return jsonify({'error': 'Data not provided'}), 403
    catId = data.get('catId')
    if not catId:
        return jsonify({'error': 'Category not provided'}), 403
    expenses = ExpenseRepository.get_by_category(catId)  
    expenses_json = [expense.serialize() for expense in expenses]
    return jsonify(expenses_json)

@expense_bp.route('/Expense/create/', methods=['POST'])  # query parameter userId
@cryptography_required
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
        new_expense = ExpenseRepository(price=price, category = catId, user=userId, expenseDate = expenseDate)
        new_expense.save()
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'message':  f'An error occurred: {str(e)}'}), 403
    
@expense_bp.route('/Expense/all/', methods=['DELETE'])
@cryptography_required
def delete_all(userId, decrypted_data):
    if not userId:
        return jsonify({'success': False, 'message':  'User not provided'}), 403
    try:
        ExpenseRepository.deleteByUser(userId)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message':  str(e)}), 403
    
@expense_bp.route('/Expense/delete/', methods=['POST'])
@cryptography_required
def delete_by_id(userId, decrypted_data):
    data = decrypted_data
    if not data:
        return jsonify({'error': 'Category not provided'}), 403
    expenseId = data.get('expenseId')
    if not expenseId:
        return jsonify({'success': False, 'message':  'ExpenseId not provided'}), 403
    try:
        ExpenseRepository.deleteById(expenseId)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message':  str(e)}), 403
    
@expense_bp.route('/Expense/edit/', methods=['POST'])
@cryptography_required
def edit(userId, decrypted_data):
    try:
        data = decrypted_data

        if not data:
            return jsonify({'success': False, 'message':  'Expense not provided'}), 403    
        id = data.get('id')
        exp = ExpenseRepository.get_by_id(id)
        if not exp:
            return jsonify({'success': False, 'message':  'Expense not found'}), 403    
        
        exp.edit(**data)
        
        expense_json = exp.serialize()
        return jsonify(expense_json)

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 403