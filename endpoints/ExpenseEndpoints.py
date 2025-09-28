from flask import Blueprint, jsonify
from models.Expense import Expense
from repositories.ExpenseRepository import ExpenseRepository
from endpoints.middlewares.auth_middleware import cryptography_required, signature_required
from utils.ResponseMaker import make_response
from utils.Constants import Messages, ExpenseMessages
from exceptions.Http import HttpException
from validators.FieldValidator import is_empty

expense_bp = Blueprint('expense', __name__)

@expense_bp.route('/Expense/', methods=['GET'])
@cryptography_required
def get_by_id(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data
        is_empty(data, ["id"])
        
        expenseId = data.get('id')

        expense = ExpenseRepository.get_by_id(expenseId, session)
        if not expense:
            return make_response(None, False, ExpenseMessages.NOT_FOUND), 200
        
        response = make_response(expense, True, ExpenseMessages.FETCHED), 200
        session.remove()

        return response
    
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
    

@expense_bp.route('/Expense/category/', methods=['GET'])
@cryptography_required
def get_by_category(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data
        is_empty(data, ["catId"])
        
        catId = data.get('catId')
        if not catId:
            return jsonify({'error': 'Category not provided'}), 403
        expenses = ExpenseRepository.get_by_category(catId, session)  
        
        response = make_response(expenses, True, ExpenseMessages.FETCHED_PLURAL), 200
        session.remove()

        return response
    
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@expense_bp.route('/Expense/', methods=['POST'])
@cryptography_required
def create_expense(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data
        is_empty(data, ["price", "expenseDate", "category"])
 
        price = data.get('price')
        expenseDate = data.get('expenseDate')
        catId = data.get('category')
        description = data.get('description')

        new_expense = Expense(
            price=price,
            category = catId,
            expenseDate = expenseDate,
            description = description
        )

        new_expense.save(session)
        response = make_response(new_expense, True, ExpenseMessages.CREATED), 200
        session.remove()
        return response

    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
    
@expense_bp.route('/Expense/all/', methods=['DELETE'])
@signature_required
def delete_all(user_id, session, user):
    try:
        ExpenseRepository.delete_all(session)
        response = make_response(None, True, ExpenseMessages.DELETED_PLURAL), 200
        session.remove()
        return response
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
    
@expense_bp.route('/Expense/', methods=['DELETE'])
@cryptography_required
def delete_by_id(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data
        is_empty(data, ["id"])

        expense_id = data.get("id")
        
        ExpenseRepository.delete_by_id(expense_id, session)
        
        response = make_response(None, True, ExpenseMessages.DELETED), 200
        session.remove()

        return response
    
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@expense_bp.route('/Expense/', methods=['PATCH'])
@cryptography_required
def edit(user_id, session, user, decrypted_data):
    try:
        data = decrypted_data
        is_empty(data, ["id"])

        expense_id = data.get("id")
        exp = ExpenseRepository.get_by_id(expense_id, session)
        if not exp:
            return make_response(None, False, ExpenseMessages.NOT_FOUND), 200    

        exp.edit(**data)
        exp.save(session)

        response = make_response(exp, True, ExpenseMessages.MODIFIED), 200
        session.remove()
        return response

    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
