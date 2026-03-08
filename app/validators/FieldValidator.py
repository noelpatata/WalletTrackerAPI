from utils.Constants import Messages
from exceptions.Http import HttpException

def is_empty(data, names):
    if not isinstance(data, dict):
        raise HttpException(Messages.INVALID_REQUEST, 400)

    if isinstance(names, str):
        names = [names]

    for name in names:
        if not data.get(name):
            raise HttpException(Messages.INVALID_REQUEST, 400)