from functools import wraps
import base64
import json
import jwt
from flask import Response, request, current_app, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from config import SECRET
from utils.multitenant import get_tenant_session
from utils.constants import Messages, AuthMessages, TokenMessages
from utils.responseMaker import make_response
from utils.cryptography import decrypt_with_private_key, sign, encrypt_with_public_key
from repositories.UserRepository import User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get('Authorization')

        if not auth_header.startswith("Bearer "):
            return make_response(None, False, AuthMessages.INVALID_HEADERS), 415
        
        token = auth_header.split(" ")[1]
        
        if not token:
            return make_response(None, False, TokenMessages.MISSING), 403
        try:
            payload = jwt.decode(
                token,
                current_app.config['PUBLIC_KEY'],
                algorithms=['RS256']
            )
            userId_from_payload = payload.get('user')
            if not userId_from_payload:
                return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
            
            user = User.get_by_id(userId_from_payload)
            if not user:
                return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
                
            tenant_session = get_tenant_session(user)

            kwargs['user_id'] = userId_from_payload
            kwargs['session'] = tenant_session

        except jwt.ExpiredSignatureError:
            return make_response(None, False, TokenMessages.EXPIRED), 401
        except jwt.InvalidTokenError:
            return make_response(None, False, TokenMessages.INVALID), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def cryptography_required(f):
    return token_required(cryptography_required(f))

def secure_endpoint(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        userId = kwargs.get('userId')
        if not userId:
            return make_response(None, False, Messages.INVALID_REQUEST), 403

        user = User.get_by_id(userId)
        if not user:
            return make_response(None, False, Messages.INVALID_REQUEST), 403

        signature_header = request.headers.get('Signature')
        encrypted_data = request.get_json(silent=True)

        if not signature_header:
            return make_response(None, False, AuthMessages.INVALID_HEADERS), 415

        try:
            signature_bytes = base64.b64decode(signature_header)
            public_key = serialization.load_pem_public_key(
                base64.b64decode(user.client_public_key)
            )

            public_key.verify(
                signature_bytes,
                SECRET.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

        except Exception:
            return make_response(None, False, AuthMessages.INVALID_HEADERS), 415

        if encrypted_data:
            decrypted_data = decrypt_with_private_key(encrypted_data, user.private_key)
            if not decrypted_data or not isinstance(decrypted_data, dict):
                return make_response(None, False, AuthMessages.INVALID_KEY), 403
        else:
            decrypted_data = {}

        kwargs['decrypted_data'] = decrypted_data
        return f(*args, **kwargs)

    return wrapper

