from flask import Blueprint
from services.ExpenseService import ExpenseService
from endpoints.middlewares.AuthMiddleware import cryptography_required, signature_required, cipher_and_sign_response
from utils.ResponseMaker import make_response
from utils.Constants import Messages, ExpenseMessages
from exceptions.Http import HttpException
from validators.FieldValidator import is_empty

expense_bp = Blueprint('expense', __name__)

@expense_bp.route('/api/v1/Expense/id', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def get_by_id(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["id"])
        expense = ExpenseService.get_by_id(decrypted_data.get('id'), session)
        response = make_response(expense, True, ExpenseMessages.FETCHED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@expense_bp.route('/api/v1/Expense/category/', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def get_by_category(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["catId"])
        expenses = ExpenseService.get_by_category(decrypted_data.get('catId'), session)
        response = make_response(expenses, True, ExpenseMessages.FETCHED_PLURAL), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@expense_bp.route('/api/v1/Expense/season/', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def get_by_season(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["seasonId"])
        expenses = ExpenseService.get_by_season(decrypted_data.get('seasonId'), session)
        response = make_response(expenses, True, ExpenseMessages.FETCHED_PLURAL), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@expense_bp.route('/api/v1/Expense/', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def create_expense(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["price", "expenseDate", "category"])
        expense = ExpenseService.create(
            price=decrypted_data.get('price'),
            expense_date=decrypted_data.get('expenseDate'),
            category_id=decrypted_data.get('category'),
            description=decrypted_data.get('description'),
            session=session
        )
        response = make_response(expense, True, ExpenseMessages.CREATED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@expense_bp.route('/api/v1/Expense/all/', methods=['DELETE'])
@signature_required
def delete_all(user_id, session, user):
    try:
        ExpenseService.delete_all(session)
        response = make_response(None, True, ExpenseMessages.DELETED_PLURAL), 200
        session.remove()
        return response
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@expense_bp.route('/api/v1/Expense/delete', methods=['POST'])
@cryptography_required
def delete_by_id(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["id"])
        ExpenseService.delete_by_id(decrypted_data.get('id'), session)
        response = make_response(None, True, ExpenseMessages.DELETED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@expense_bp.route('/api/v1/Expense/', methods=['PATCH'])
@cryptography_required
@cipher_and_sign_response
def edit(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["id"])
        expense = ExpenseService.edit(decrypted_data.get('id'), decrypted_data, session)
        response = make_response(expense, True, ExpenseMessages.MODIFIED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
