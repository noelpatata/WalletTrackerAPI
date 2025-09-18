import datetime
import base64
import jwt
from flask import Blueprint, request, current_app
from utils.cryptography import generate_private_key, generate_private_key_string, generate_public_key_string, verify_signature
from utils.constants import  Messages, AuthMessages, UserMessages
from utils.multitenant import create_tenant_user_and_db
from utils.responseMaker import make_response
from repositories.UserRepository import UserRepository
from models.User import User
from endpoints.middlewares.authentication import token_required
auth_bp = Blueprint('authentication', __name__)

@auth_bp.route("/login/", methods=['POST'])
def login():
    try:
        auth = request.get_json()
        if auth:
            user = UserRepository.get_by_username(auth.get('username'))
            
            if user is None:
                return make_response(None, False, Messages.INVALID_REQUEST), 200
            if(UserRepository.check_password(user, auth.get('password'))):
                payload = {'user': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)}
                token = jwt.encode(
                    payload,
                    current_app.config['PRIVATE_KEY'],
                    algorithm='RS256')
                return make_response({'token': token}, True, AuthMessages.LOGGED_IN), 200
            else:
                return make_response(None, False, UserMessages.USER_NOT_FOUND), 404

        return make_response(None, False, Messages.INVALID_REQUEST), 200
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    
@auth_bp.route("/register/", methods=['POST'])
def register():
    
    data = request.get_json()
    if not data:
        return make_response(None, False, Messages.INVALID_REQUEST), 200
    
    new_username = data.get('username')
    if not new_username or new_username == "":
        return make_response(None, False, Messages.INVALID_REQUEST), 200
    
    if UserRepository.check_exists(new_username):
        return make_response(None, False, AuthMessages.ALREADY_EXISTS), 200
    
    private_key = generate_private_key() 
    private_keystring = generate_private_key_string(private_key)
    public_keystring = generate_public_key_string(private_key)
    
    new_user = User(
        username = new_username,
        private_key = private_keystring,
        public_key = public_keystring,
        client_public_key = ""
    )
    new_user.set_password(data.get('password'))
    new_user.save()

    try:
        db_username, db_password = create_tenant_user_and_db(new_user)
        new_user.db_username = db_username
        new_user.db_password = db_password
        new_user.save()

    except Exception as e:
        new_user.delete()
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    return make_response(new_user, True, UserMessages.CREATED)

@auth_bp.route("/autoLogin/", methods=['POST'])
def auto_login():
    try:
        data = request.get_json()
        if not data or 'userId' not in data or 'ciphered' not in data:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        user_id = data.get('userId')
        ciphered_text_bs64 = data.get('ciphered')

        if not user_id or not ciphered_text_bs64:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        public_key_pem = base64.b64decode(user.client_public_key)
        
        if not public_key_pem:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        verified = verify_signature(public_key_pem, ciphered_text_bs64)
        if(not verified):
            return make_response(None, False, AuthMessages.INVALID_HEADERS), 415

        payload = {
            'user': user.id,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        }
        token = jwt.encode(
            payload,
            current_app.config['PRIVATE_KEY'],
            algorithm='RS256'
        )

        return make_response({'userId': user.id, 'token': token}, True, AuthMessages.LOGGED_IN), 200
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500

@auth_bp.route("/getUserServerPubKey/", methods=['GET'])
@token_required
def get_user_pub_key(user_id, session):
    try:

        if not user_id:
            return make_response(None, False, Messages.INVALID_REQUEST), 200
        
        user = UserRepository.get_by_id(user_id)
        if not user:
            return make_response(None, False, Messages.INVALID_REQUEST), 200
        
        return make_response({'userId': user.id, 'publicKey':user.public_key}, True, AuthMessages.FETCHED_SERVER_PUB_KEY), 200
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    

@auth_bp.route("/setUserClientPubKey/", methods=['POST'])
@token_required
def set_user_pub_key(user_id, session):
    try:
        data = request.get_json()

        if not data:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        pub_key_b64 = data.get('publicKey')
        if not pub_key_b64:
            return make_response(None, False, Messages.INVALID_REQUEST), 200

        if not user_id:
            return make_response(None, False, Messages.INVALID_REQUEST), 200
        
        user = UserRepository.get_by_id(user_id)
        user.client_public_key = pub_key_b64
        user.save()
        
        return make_response(None, True, AuthMessages.ASSIGNED_SERVER_CLIENT_KEY), 200
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    
    