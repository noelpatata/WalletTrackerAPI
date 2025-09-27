from utils.constants import Messages
from exceptions.HttpException import HttpError

def validate_name_and_id(data):
    if not data('name') or not data('id'):
        raise HttpError(Messages.INVALID_REQUEST, 404)