from utils.constants import Messages
from exceptions.HttpException import HttpError

def validate_expense_category_id(data):
    if not data('id'):
        raise HttpError(Messages.INVALID_REQUEST, 404)