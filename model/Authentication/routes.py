import base64
import sys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import datetime
from flask import request, jsonify, make_response, current_app
import jwt
from . import auth_bp
from .User import User
from strings import Errors

def token_required(f):
    def decorated(*args, **kwargs):

        cipheredText = request.args.get('cipherered')
        auth_header = request.headers.get('Authorization')

        if not cipheredText or not auth_header:
            return jsonify({'error': 'Authentication error'}), 403

        if not auth_header.startswith("Bearer "):
            return jsonify({'error': 'Invalid Authorization header format. Use Bearer <token>'}), 403

        token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'error': Errors.missing}), 403
        try:
            payload = jwt.decode(
                token,
                current_app.config['PUBLIC_KEY'],
                algorithms=['RS256']
            )
            userId_from_payload = payload.get('user')
            if not userId_from_payload:
                return jsonify({'error': 'Authentication error'}), 403
            
            user = User.get_by_id(userId_from_payload)
            if not user:
                return jsonify({'error': 'Authentication error'}), 403
            
            public_key_pem = user.public_key.encode('utf-8')  # Assuming `public_key` is stored as a string in the DB
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )

            # Decode the Base64-encoded ciphered text
            ciphered_bytes = base64.b64decode(cipheredText)

            # Decrypt the ciphered text using the public key
            decrypted_text = public_key.decrypt(
                ciphered_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if decrypted_text != "somerandomtext":
                return jsonify({'error': 'Authentication error'}), 403

            kwargs['userId'] = userId_from_payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': Errors.expired}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': Errors.invalid}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated


@auth_bp.route("/login")
def login():
    auth = request.authorization
    if auth:
        
        user = User.query.filter(User.username == auth.username).first()
        
        if user is None:
            return make_response('User not found', 404, {'WWW-Authenticate': 'Basic realm="User Not Found"'})
        if(user.CorrectPassword(auth.password)):
            payload = {'user': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)}
            token = jwt.encode(
                payload,
                current_app.config['PRIVATE_KEY'],
                algorithm='RS256')
            return jsonify({'userId': user.id, 'token': token}), 200
        else:
            return make_response('User not found', 404, {'WWW-Authenticate': 'Basic realm="User Not Found"'})

    return make_response('Could not Verify', 401, {'WWW-Authenticate': 'Basic realm ="Login Required"'})

@auth_bp.route("/autologin")
def autologin():
    try:
        user_id = request.args.get('userId')
    
        #validation
        if not user_id:
            return jsonify({'error': 'No userId passed'}), 500   
        
        user = User.query.filter(User.id == user_id).first()
        if user is None:
            return jsonify({'error': 'User not found'}), 404
        
        payload = {'user': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)}
        token = jwt.encode(
            payload,
            current_app.config['PRIVATE_KEY'],
            algorithm='RS256')
        return jsonify({'userId': user.id, 'token': token}), 200
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500
        
    