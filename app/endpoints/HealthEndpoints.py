from flask import Blueprint
from utils.ResponseMaker import make_response
from utils.Constants import Messages

health_bp = Blueprint('health', __name__)

@health_bp.route('/api/v1/health', methods=['GET'])
def health_check():
    try:
        return make_response(None, True, Messages.SUCCESS), 200

    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
