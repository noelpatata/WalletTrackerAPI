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

@expense_bp.route('/Expense/', methods=['POST'])  # query parameter userId
@token_required
def create_expense_category():
    try:
        #data extraction
        userId = request.args.get('userId')
        data = request.get_json()
        
        price = data.get('price')
        expenseDate = data.get('expenseDate')
        catId = data.get('category')

        #validation
        if not price:
            return jsonify({'error': 'price not provided'}), 500    
        if not expenseDate:
            return jsonify({'error': 'expenseDate not provided'}), 500    
        if not catId:
            return jsonify({'error': 'catId not provided'}), 500
           
        #save data
        new_expense = Expense(price=price, category = catId, user=userId, expenseDate = expenseDate)
        new_expense.save()
        return jsonify(new_expense.serialize()), 201

    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@expense_bp.route('/Expense/total/', methods=['GET'])  # query parameter userId, catId
@token_required
def get_total_by_category():
    catId = request.args.get('catId')
    if not catId:
        return jsonify({'error': 'Category not provided'}), 403

    try:
        total = Expense.getTotalByCategory(catId)
        return jsonify({'total': total}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@expense_bp.route('/Expense/all/', methods=['DELETE'])
@token_required
def delete_all():
    userId = request.args.get('userId')
    if not userId:
        return jsonify({'error': 'User not provided'}), 403
    try:
        Expense.deleteByUser(userId)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@expense_bp.route('/Expense/', methods=['DELETE'])
@token_required
def delete_by_id():
    expenseId = request.args.get('expenseId')
    if not expenseId:
        return jsonify({'error': 'ExpenseId not provided'}), 403
    try:
        Expense.deleteById(expenseId)
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500