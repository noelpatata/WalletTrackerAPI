from flask import Blueprint, jsonify
from repositories.UserRepository import User
from utils.multitenant import get_tenant_session
from repositories.ExpenseCategoryRepository import ExpenseCategory
from repositories.ExpenseRepository import Expense
from endpoints.middlewares.authentication import encrypt_and_sign_data
from utils.responseMaker import make_response
from utils.constants import Messages, AuthMessages


expensecategory_bp = Blueprint('expensecategory', __name__)

@expensecategory_bp.route('/ExpenseCategory/', methods=['GET'])
@encrypt_and_sign_data
def get_by_id(userId, decrypted_data):
    try:
        data = decrypted_data
        if not data:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        catId = data.get('catId')
        if not catId:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        category = ExpenseCategory.getById(catId)
        if not category:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        total = Expense.getTotalByCategory(category.id)
        category.setTotal(total)

        return make_response(category, True), 200
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    

@expensecategory_bp.route('/ExpenseCategory/all', methods=['GET'])
@encrypt_and_sign_data
def get_all(userId, decrypted_data):
    try:
        if not userId:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200

        user = User.getById(userId)
        if not user:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        session = get_tenant_session(user)
        categories = ExpenseCategory.getAll(session)
        for category in categories:
            total = Expense.getTotalByCategory(category.id, session)
            category.setTotal(total) 
        cat_json = [category.getColumns() for category in categories]
        session.remove()
        return jsonify(cat_json)

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    

@expensecategory_bp.route('/ExpenseCategory/create/', methods=['POST'])  # query parameter userId
@encrypt_and_sign_data
def create_expense_category(userId, decrypted_data):
    try:
        data = decrypted_data
        catName = data.get('name')

        if not catName or not userId:
            return jsonify({'success': False, 'message': 'Invalid data'}), 403    
        
        user = User.getById(userId)
        if not user:
            raise ValueError("User not found")
        
        session = get_tenant_session(user)
        new_category = ExpenseCategory(name=catName, user=userId)
        new_category.save(session)
        return jsonify(new_category.toJsonDict()), 200

    except Exception as e:
        return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 403
@expensecategory_bp.route('/ExpenseCategory/delete/', methods=['POST'])
@encrypt_and_sign_data
def delete_by_id(userId, decrypted_data):
    try:
        data = decrypted_data
        if not data:
            return jsonify({'success': False, 'message': 'CategoryId not provided'}), 403    
        catId = data.get('catId')

        if not catId:
            return jsonify({'success': False, 'message': 'CategoryId not provided'}), 403    

        ExpenseCategory.deleteById(catId)
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 403
    
@expensecategory_bp.route('/ExpenseCategory/editName/', methods=['POST'])
@encrypt_and_sign_data
def edit_name(userId, decrypted_data):
    try:
        data = decrypted_data

        if not data:
            return jsonify({'success': False, 'message': 'Category not provided'}), 403    
        
        cat = ExpenseCategory.getById(data.get('id'))
        if not cat:
            return jsonify({'success': False, 'message': 'Category not provided'}), 403    
        cat.editName(data.get('name'))
        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 403