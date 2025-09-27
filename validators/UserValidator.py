from utils.constants import UserMessages
from exceptions.HttpException import HttpError

def validate_user(user):
    if not user or not user.id:
        raise HttpError(UserMessages.USER_NOT_FOUND, 404)