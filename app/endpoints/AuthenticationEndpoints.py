from flask import Blueprint, request, current_app
from services.UserService import UserService
from utils.Constants import Messages, AuthMessages, UserMessages
from utils.ResponseMaker import make_response
from endpoints.middlewares.AuthMiddleware import token_required
from exceptions.Http import HttpException
from validators.FieldValidator import is_empty

auth_bp = Blueprint('authentication', __name__)

@auth_bp.route("/api/v1/login/", methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        token = UserService.login(data.get('username'), data.get('password'))
        return make_response({'token': token}, True, AuthMessages.LOGGED_IN), 200

    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@auth_bp.route("/api/v1/register/", methods=['POST'])
def register():
    try:
        if not current_app.config['ENABLE_REGISTER']:
            return make_response(None, False, Messages.INVALID_REQUEST), 403

        data = request.get_json()
        if not data:
            return make_response(None, False, Messages.INVALID_REQUEST), 200
        is_empty(data, ["username", "password"])

        created_user = UserService.register(data.get('username'), data.get('password'))
        return make_response(created_user, True, UserMessages.CREATED)

    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@auth_bp.route("/api/v1/getUserServerPubKey/", methods=['GET'])
@token_required
def get_user_pub_key(user_id, session, user):
    try:
        fetched_user = UserService.get_by_id(user_id)
        return make_response({'userId': fetched_user.id, 'publicKey': fetched_user.public_key}, True, AuthMessages.FETCHED_SERVER_PUB_KEY), 200

    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@auth_bp.route("/api/v1/setUserClientPubKey/", methods=['POST'])
@token_required
def set_user_pub_key(user_id, session, user):
    try:
        data = request.get_json()
        if not data:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        pub_key_b64 = data.get('publicKey')
        if not pub_key_b64:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        UserService.set_client_public_key(user_id, pub_key_b64)
        return make_response(None, True, AuthMessages.ASSIGNED_SERVER_CLIENT_KEY), 200

    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
