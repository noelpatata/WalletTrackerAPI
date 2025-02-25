from flask import jsonify, request
from . import expense_bp
from .Expense import Expense
from ..Authentication.routes import encrypt_and_sign_data


# Endpoints
@expense_bp.route('/Expense/Id/', methods=['GET']) #query parameter userId, catId
@encrypt_and_sign_data
def get_by_id(userId):
    expenseId = request.args.get('expenseId')
    if not expenseId:
        return jsonify({'error': 'Expense id not provided'}), 203
    expense = Expense.get_by_id(expenseId)
    expense_json = expense.serialize()
    return jsonify(expense_json)

@expense_bp.route('/Expense/', methods=['GET']) #query parameter userId, catId
@encrypt_and_sign_data
def get_by_category(userId):
    catId = request.args.get('catId')
    if not catId:
        return jsonify({'error': 'Category not provided'}), 203
    expenses = Expense.getByCategory(catId)
    expenses_json = [expense.serialize() for expense in expenses]
    return jsonify(expenses_json)

@expense_bp.route('/Expense/create', methods=['POST'])  # query parameter userId
@encrypt_and_sign_data
def create_expense(userId):
    try:
        #data extraction
        data = request.get_json()
        userId = data.get('user')
        price = data.get('price')
        expenseDate = data.get('expenseDate')
        catId = data.get('category')

        #validation
        if not price or not expenseDate or not catId or not userId:
            return jsonify({'success': False, 'message': 'Bad request'}), 203    
        
        #save data
        new_expense = Expense(price=price, category = catId, user=userId, expenseDate = expenseDate)
        new_expense.save()
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'message':  f'An error occurred: {str(e)}'}), 203

@expense_bp.route('/Expense/total/', methods=['GET'])  # query parameter userId, catId
@encrypt_and_sign_data
def get_total_by_category(userId):
    catId = request.args.get('catId')
    if not catId:
        return jsonify({'success': False, 'message':  'Category not provided'}), 403

    try:
        total = Expense.getTotalByCategory(catId)
        return jsonify({'total': total}), 200
    except Exception as e:
        return jsonify({'success': False, 'message':  str(e)}), 500
    
@expense_bp.route('/Expense/all/', methods=['DELETE'])
@encrypt_and_sign_data
def delete_all(userId):
    if not userId:
        return jsonify({'success': False, 'message':  'User not provided'}), 203
    try:
        Expense.deleteByUser(userId)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message':  str(e)}), 203
    
@expense_bp.route('/Expense/', methods=['DELETE'])
@encrypt_and_sign_data
def delete_by_id(userId):
    expenseId = request.args.get('expenseId')
    if not expenseId:
        return jsonify({'success': False, 'message':  'ExpenseId not provided'}), 203
    try:
        Expense.deleteById(expenseId)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'message':  str(e)}), 203
    
@expense_bp.route('/Expense/edit', methods=['POST'])
@encrypt_and_sign_data
def edit(userId):
    try:
        data = request.get_json()

        if not data:
            return jsonify({'success': False, 'message':  'Expense not provided'}), 203    
        id = data.get('id')
        exp = Expense.get_by_id(id)
        if not exp:
            return jsonify({'success': False, 'message':  'Expense not found'}), 203    
        
        exp.edit(**data)
        
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 203