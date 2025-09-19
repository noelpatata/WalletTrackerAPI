from utils.constants import UserMessages
from utils.responseMaker import make_response

def validate_user(user):
    if not user:
        return None, make_response(None, False, UserMessages.USER_NOT_FOUND), 404
    return user, None