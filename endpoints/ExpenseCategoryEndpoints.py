from flask import Blueprint
from endpoints.middlewares.authentication import protected_endpoint
from utils.responseMaker import make_response
from utils.constants import Messages, AuthMessages, ExpenseCategoryMessages
from repositories.ExpenseCategoryRepository import ExpenseCategoryRepository
from models.ExpenseCategory import ExpenseCategory


expensecategory_bp = Blueprint('expensecategory', __name__)

@expensecategory_bp.route('/ExpenseCategory/', methods=['GET'])
@protected_endpoint
def get_by_id(userId, session, decrypted_data):
    try:
        data = decrypted_data
        if not data:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        catId = data.get('catId')
        if not catId:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        category = ExpenseCategoryRepository.get_by_id(catId, session)
        if not category:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200

        return make_response(category, True, ExpenseCategoryMessages.FETCHED_SUCCESSFULLY), 200
    
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    

@expensecategory_bp.route('/ExpenseCategory/all', methods=['GET'])
@protected_endpoint
def get_all(userId, session, decrypted_data):
    try:
        if not userId:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        categories = ExpenseCategoryRepository.get_all(session)
        session.remove()
        
        return make_response(categories, True, ExpenseCategoryMessages.FETCHED_SUCCESSFULLY_PLURAL), 200

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    

@expensecategory_bp.route('/ExpenseCategory/', methods=['POST'])
@protected_endpoint
def create_expense_category(userId, session, decrypted_data):
    try:
        data = decrypted_data
        catName = data.get('name')

        if not catName or not userId:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        new_category = ExpenseCategory(name=catName)
        new_category.save(session)

        session.remove()

        return make_response(new_category, True, ExpenseCategoryMessages.CREATED), 200

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    
@expensecategory_bp.route('/ExpenseCategory/', methods=['DELETE'])
@protected_endpoint
def delete_by_id(userId, session, decrypted_data):
    try:
        data = decrypted_data
        if not data:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        catId = data.get('catId')

        if not catId:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200

        ExpenseCategoryRepository.delete_by_id(catId, session)
        return make_response(None, True, ExpenseCategoryMessages.DELETED), 200

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    
@expensecategory_bp.route('/ExpenseCategory/editName/', methods=['PATCH'])
@protected_endpoint
def edit_name(userId, session, decrypted_data):
    try:
        data = decrypted_data

        if not data:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        cat = ExpenseCategoryRepository.get_by_id(data.get('id'), session)
        if not cat:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
        cat.setName(data.get('name'))
        return make_response(None, True, ExpenseCategoryMessages.MODIFIED), 200

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500