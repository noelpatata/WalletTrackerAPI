from functools import wraps
from flask import request
from utils.Multitenant import get_tenant_session
from utils.Constants import Messages, AuthMessages, TokenMessages
from utils.ResponseMaker import make_response
from utils.Cryptography import hybrid_decryption, decode_jwt, verify_signature
from repositories.UserRepository import UserRepository
from validators.UserValidator import validate_user
from exceptions.Http import HttpException

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        try:
            auth_header = request.headers.get('Authorization')

            if not auth_header:
                raise HttpException(AuthMessages.INVALID_HEADERS, 415)
            
            if not auth_header.startswith("Bearer "):
                raise HttpException(AuthMessages.INVALID_HEADERS, 415)
            
            token = auth_header.split(" ")[1]
            if not token:
                raise HttpException(TokenMessages.MISSING, 401)
            
            payload = decode_jwt(token)

            user_id_from_payload = payload.get('user')            
            user = UserRepository.get_by_id(user_id_from_payload)
            validate_user(user)
            
            tenant_session = get_tenant_session(user)
            
            kwargs['user_id'] = user.id
            kwargs['session'] = tenant_session
            kwargs['user'] = user
        
        except HttpException as e:
            return make_response(None, False, e.message, e.inner_exception), e.status_code
        except Exception as e:
            return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
        

        return f(*args, **kwargs)
    return wrapper

def signed_header(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            user_id = kwargs.get('user_id')
            user_from_decorator = kwargs.get('user')
            if not user_from_decorator:
                user_from_decorator = UserRepository.get_by_id(user_id)
                validate_user(user_from_decorator)

            signature_header = request.headers.get('Signature')
            verify_signature(user_from_decorator.client_public_key, signature_header)

            return f(*args, **kwargs)
        
        except HttpException as e:
            return make_response(None, False, e.message, e.inner_exception), e.status_code
        except Exception as e:
            return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
        

    return wrapper

def ciphered_body(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        try:
            user_id = kwargs.get('user_id')

            user_from_decorator = kwargs.get('user')
            if not user_from_decorator:
                user_from_decorator = UserRepository.get_by_id(user_id)
                validate_user(user_from_decorator)
            
            encrypted_data = request.get_json(silent=True)
            
            decrypted_data = hybrid_decryption(encrypted_data, user_from_decorator.private_key)
            if not decrypted_data:
                return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
        
            kwargs['decrypted_data'] = decrypted_data
            
            
            return f(*args, **kwargs)
        
        except HttpException as e:
            return make_response(None, False, e.message, e.inner_exception), e.status_code
        
        except Exception as e:
            return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
            
        
    
    return wrapper

def cryptography_required(f):
    return token_required(signed_header(ciphered_body(f)))

def signature_required(f):
    return token_required(signed_header(f))