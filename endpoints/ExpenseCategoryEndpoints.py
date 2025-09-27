from flask import Blueprint
from endpoints.middlewares.auth_middleware import cryptography_required, signature_required
from utils.responseMaker import make_response
from utils.constants import Messages, ExpenseCategoryMessages
from repositories.ExpenseCategoryRepository import ExpenseCategoryRepository
from models.ExpenseCategory import ExpenseCategory
from exceptions.HttpException import HttpError
from validators.ExpenseCategory.EditExpenseCategory import validate_name
from validators.ExpenseCategory.CreateExpenseCategoryValidator import validate_id

expensecategory_bp = Blueprint('expensecategory', __name__)

@expensecategory_bp.route('/ExpenseCategory/', methods=['GET'])
@cryptography_required
def get_by_id(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data
        
        catId = data.get('id')
        if not catId:
            return make_response(None, False, Messages.INVALID_REQUEST), 200
        
        category = ExpenseCategoryRepository.get_by_id(catId, session)
        if not category:
            return make_response(None, False, ExpenseCategoryMessages.NOT_FOUND), 200

        response = make_response(category, True, ExpenseCategoryMessages.FETCHED), 200
        session.remove()

        return response
    
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
    

@expensecategory_bp.route('/ExpenseCategory/all', methods=['GET'])
@signature_required
def get_all(user_id, session, user):
    try:  
        categories = ExpenseCategoryRepository.get_all(session)
        
        response = make_response(categories, True, ExpenseCategoryMessages.FETCHED_PLURAL), 200
        session.remove()

        return response

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
    

@expensecategory_bp.route('/ExpenseCategory/', methods=['POST'])
@cryptography_required
def create_expense_category(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data
        validate_name(data)
        
        cat_name = data.get("name")
        
        new_category = ExpenseCategory(name=cat_name)
        new_category.save(session)


        response = make_response(new_category, True, ExpenseCategoryMessages.CREATED), 200
        session.remove()

        return response

    except HttpError as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
    
@expensecategory_bp.route('/ExpenseCategory/', methods=['DELETE'])
@cryptography_required
def delete_by_id(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data
        catId = data.get('id')

        if not catId:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        ExpenseCategoryRepository.delete_by_id(catId, session)
        session.remove()
        
        return make_response(None, True, ExpenseCategoryMessages.DELETED), 200

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
    
@expensecategory_bp.route('/ExpenseCategory/', methods=['PATCH'])
@cryptography_required
def edit_name(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data

        if not data:
            return make_response(None, False, Messages.INVALID_REQUEST), 200
        
        cat = ExpenseCategoryRepository.get_by_id(data.get('id'), session)
        if not cat:
            return make_response(None, False, Messages.INVALID_REQUEST), 200
        
        cat.setName(data.get('name'))
        cat.save(session)

        return make_response(None, True, ExpenseCategoryMessages.MODIFIED), 200

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500