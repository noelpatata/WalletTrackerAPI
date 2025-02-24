import json
import re
import base64
import sys
import generateKeys
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

        cipher_header = request.headers.get('Cipher')
        auth_header = request.headers.get('Authorization')
        if not cipher_header or not auth_header:
            return jsonify({'error': 'Authentication error'}), 403

        
        if not auth_header.startswith("Bearer "):
            return jsonify({'error': 'Invalid Authorization header format. Use Bearer <token>'}), 403

        cipheredTextb64 = cipher_header
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
            public_key_pem = base64.b64decode(user.client_public_key)
          # Ensure no extra whitespace
            if not public_key_pem:
                return jsonify({'success': False, 'message': 'Invalid data'}), 203

            # Deserialize the private key
            public_key = serialization.load_pem_public_key(
                public_key_pem
            )

            # Decode the Base64-encoded ciphered text
            try:
                signature_bytes = base64.b64decode(cipheredTextb64)
            except Exception as e:
                return jsonify({'success': False, 'message': 'Invalid data'}), 203
            except Exception as e:
                return jsonify({'success': False, 'message': f'Invalid data'}), 203
            
            public_key.verify(
                signature_bytes,
                b"s0m3r4nd0mt3xt",
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            kwargs['userId'] = userId_from_payload
        except jwt.ExpiredSignatureError:
            return jsonify({'error': Errors.expired}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': Errors.invalid}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def encrypt_with_public_key(data, public_key_str):
    public_key = serialization.load_pem_public_key(base64.b64decode(public_key_str), backend=default_backend())
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_data).decode()

# Helper function to sign data with the user's private key
def sign_with_private_key(data, private_key_str):
    private_key = serialization.load_pem_private_key(base64.b64decode(private_key_str), password=None, backend=default_backend())
    signature = private_key.sign(
        data.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# Middleware to intercept requests and responses
def encrypt_and_sign_data(func):
    @token_required
    def wrapper(userId, *args, **kwargs):
        try:
            # Fetch the user and their keys from the database
            
            user = User.query.get(userId)
            if not user:
                return jsonify({'success': False, 'message': 'User not found'}), 203
            
            # Encrypt the incoming request data using the user's client public key
            response = func(userId, *args, **kwargs)
            
            if response.status_code == 200 or response.status_code == 201:
                response_data = response.get_json()  # Get the response JSON data
                signature = sign_with_private_key("s0m3r4nd0mt3xt", user.private_key)
                if response_data:
                    # Convert the entire JSON object to a string (to be encrypted)
                    json_str = json.dumps(response_data)
                    
                    # Encrypt JSON
                    encrypted_json = encrypt_with_public_key(json_str, user.client_public_key)
                    response.set_data(jsonify({'signature':f'{signature}', 'encrypted_data': encrypted_json}).data)
            
            return response
        except Exception as e:
            return jsonify({'success': False, 'message': f'An error occurred: {str(e)}'}), 203
    return wrapper

@auth_bp.route("/register/", methods=['POST'])
def register():
    
    # validation
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    
    newUserName = data.get('username')
    if not newUserName or newUserName == "":
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    
    if User.check_exists(newUserName):
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    
    #user creation   
    privkey = generateKeys.generate_private_key() 
    privkeystring = generateKeys.generate_private_key_string(privkey)
    pubkeystring = generateKeys.generate_public_key_string(privkey)
    
    newUser = User(
        username = newUserName,
        private_key = privkeystring,
        public_key = pubkeystring
    )

    
    newUser.set_password(data.get('password'))
    
    return jsonify({'userId': newUser.id, 'public_key':newUser.public_key}), 200

@auth_bp.route("/login/")
def login():
    auth = request.authorization
    if auth:
        user = User.query.filter(User.username == auth.username).first()
        
        if user is None:
            return jsonify({'success': False, 'message': 'Invalid data'}), 203
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

@auth_bp.route("/autologin/", methods=['POST'])
def autologin():
    try:
        data = request.get_json()
        if not data or 'userId' not in data or 'ciphered' not in data:
            return jsonify({'success': False, 'message': 'Invalid data'}), 203

        user_id = data.get('userId')
        ciphered_textbs64 = data.get('ciphered')

        # Validate userId and ciphered text
        if not user_id or not ciphered_textbs64:
            return jsonify({'success': False, 'message': 'Invalid data'}), 203

        # Fetch the user from the database
        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'success': False, 'message': 'Invalid data'}), 203

        # Load the private key (assuming it's stored securely in the user object)
        public_key_pem = base64.b64decode(user.client_public_key)
          # Ensure no extra whitespace
        if not public_key_pem:
            return jsonify({'success': False, 'message': 'Invalid data'}), 203

            # Deserialize the private key
        public_key = serialization.load_pem_public_key(
            public_key_pem
        )

            # Decode the Base64-encoded ciphered text
        try:
            signature_bytes = base64.b64decode(ciphered_textbs64)
        except Exception as e:
            return jsonify({'success': False, 'message': 'Invalid data'}), 203
        except Exception as e:
            return jsonify({'success': False, 'message': f'Invalid data'}), 203
            
        public_key.verify(
            signature_bytes,
            b"s0m3r4nd0mt3xt",
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Generate a JWT token
        payload = {
            'user': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        token = jwt.encode(
            payload,
            current_app.config['PRIVATE_KEY'],  # Ensure this is your app's private key
            algorithm='RS256'
        )

        # Return the response
        return jsonify({'userId': user.id, 'token': token}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
@auth_bp.route("/getUserServerPubKey/", methods=['POST'])
def get_user_pub_key():
    
    # validation
    auth = request.authorization
    if not auth:
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    
    username = auth.username
    if not username or username == "":
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    
    user = User.query.filter(User.username == auth.username).first()
    if not user:
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    if(not user.CorrectPassword(auth.password)):
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    
    return jsonify({'userId': user.id, 'public_key':user.public_key}), 200

@auth_bp.route("/setUserClientPubKey/", methods=['POST'])
def set_user_pub_key():
    
    # validation
    auth = request.authorization
    if not auth:
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    data = request.get_json()

    if not data:
        return jsonify({'success': False, 'message': 'Invalid data'}), 203

    pub_key_b64 = data.get('publicKey')
    if not pub_key_b64:
        return jsonify({'success': False, 'message': 'Invalid data'}), 203

    
    username = auth.username
    if not username or username == "":
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    
    user = User.query.filter(User.username == auth.username).first()
    if not user:
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    if(not user.CorrectPassword(auth.password)):
        return jsonify({'success': False, 'message': 'Invalid data'}), 203
    user.client_public_key = pub_key_b64
    user.save()
    return jsonify({'success': True, 'message':'Public key sent successfully'}), 200
    