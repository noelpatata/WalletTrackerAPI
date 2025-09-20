from utils.constants import UserMessages
from utils.responseMaker import make_response
from exceptions.HttpException import HttpError

def validate_user(user):
    if not user:
        raise HttpError(UserMessages.USER_NOT_FOUND, 404)