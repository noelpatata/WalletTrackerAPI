from utils.Constants import UserMessages
from exceptions.Http import HttpException

def validate_user(user):
    if not user or not user.id:
        raise HttpException(UserMessages.USER_NOT_FOUND, 400)