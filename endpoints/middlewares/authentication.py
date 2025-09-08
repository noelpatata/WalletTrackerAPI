from functools import wraps
import base64
import json
import jwt
from flask import Response, request, current_app, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from config import SECRET
from utils.constants import AuthMessages, TokenMessages
from utils.responseMaker import make_response
from utils.cryptography import decrypt_with_private_key, sign_with_private_key, encrypt_with_public_key
from repositories.UserRepository import User

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        cipher_header = request.headers.get('Cipher')

        auth_header = request.headers.get('Authorization')
        encrypted_data = request.get_json(silent = True)
        if not cipher_header or not auth_header:
            return make_response(None, False, AuthMessages.INVALID_HEADERS), 415

        
        if not auth_header.startswith("Bearer "):
            return make_response(None, False, AuthMessages.INVALID_HEADERS), 415

        ciphered_text_b64 = cipher_header
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
            public_key_pem = base64.b64decode(user.client_public_key)
          
            if not public_key_pem:
                return make_response(None, False, AuthMessages.INVALID_KEY), 403

            public_key = serialization.load_pem_public_key(
                public_key_pem
            )

            try:
                signature_bytes = base64.b64decode(ciphered_text_b64)
            except Exception as e:
                return make_response(None, False, AuthMessages.INVALID_HEADERS), 415
            
            public_key.verify(
                signature_bytes,
                SECRET.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            if encrypted_data:
                decrypted_data = decrypt_with_private_key(encrypted_data, user.private_key)
                if not decrypted_data or not isinstance(decrypted_data, dict):
                    return make_response(None, False, AuthMessages.INVALID_KEY), 403
            else: 
                decrypted_data = ''
                
            
            kwargs['userId'] = userId_from_payload
            kwargs['decrypted_data'] = decrypted_data

        except jwt.ExpiredSignatureError:
            return make_response(None, False, TokenMessages.EXPIRED), 401
        except jwt.InvalidTokenError:
            return make_response(None, False, TokenMessages.INVALID), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def encrypt_and_sign_data(func):
    @token_required
    @wraps(func)
    def wrapper(userId, *args, **kwargs):
        try:

            user = User.query.get(userId)
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 403
            
            response = func(userId, *args, **kwargs) #get response from original request

            status_code = 200
            if isinstance(response, tuple):
                response, status_code = response

            if not isinstance(response, Response):  
                response = jsonify(response)

            # Handle encryption & signing for both GET & POST methods
            if request.method in ['GET', 'POST'] and status_code in [200, 201]:
                try:
                    response_data = response.get_json()

                    signature = sign_with_private_key(SECRET, user.private_key)
                    json_str = json.dumps(response_data, ensure_ascii=False)
                    encrypted_json = encrypt_with_public_key(json_str, user.client_public_key)
                    encrypted_response = jsonify({'signature': signature, 'encrypted_data': encrypted_json})
                    encrypted_response.status_code = status_code
                    return encrypted_response # this is the actual response from the server    
                except Exception as ex:
                    return jsonify({'success': False, 'message': f'Invalid data'}), 403        
                
                    
            response.status_code = status_code
            return response

        except Exception as e:
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 403

    return wrapper