from functools import wraps
from flask import request
from utils.multitenant import get_tenant_session
from utils.constants import AuthMessages
from utils.responseMaker import make_response
from utils.cryptography import decrypt_with_private_key, decode_jwt, verify_signature
from repositories.UserRepository import UserRepository
from validators.UserValidator import validate_user

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        auth_header = request.headers.get('Authorization')

        if not auth_header.startswith("Bearer "):
            return make_response(None, False, AuthMessages.INVALID_HEADERS), 415
        
        token = auth_header.split(" ")[1]
        payload = decode_jwt(token)

        user_id_from_payload = payload.get('user')            
        user = UserRepository.get_by_id(user_id_from_payload)
        validate_user(user)
        
        tenant_session = get_tenant_session(user)
        
        kwargs['user_id'] = user.id
        kwargs['session'] = tenant_session
        kwargs['user'] = user

        return f(*args, **kwargs)
    return wrapper

def signed_header(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        user_id = kwargs.get('user_id')
        user_from_decorator = kwargs.get('user')
        if not user_from_decorator:
            user = UserRepository.get_by_id(user_id)
            validate_user(user)

        signature_header = request.headers.get('Signature')
        verify_signature(user.client_public_key, signature_header)

        return f(*args, **kwargs)

    return wrapper

def ciphered_body(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        user_id = kwargs.get('user_id')

        user_from_decorator = kwargs.get('user')
        if not user_from_decorator:
            user = UserRepository.get_by_id(user_id)
            validate_user(user)
        
        encrypted_data = request.get_json(silent=True)
        
        decrypted_data = decrypt_with_private_key(encrypted_data, user.private_key)

        kwargs['decrypted_data'] = decrypted_data
        
        return f(*args, **kwargs)
    
    return wrapper

def cryptography_required(f):
    return token_required(signed_header(ciphered_body(f)))

def signature_required(f):
    return token_required(signed_header(f))