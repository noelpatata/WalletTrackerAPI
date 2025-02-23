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

@auth_bp.route("/register", methods=['POST'])
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
    privkeystring = generateKeys.generate_public_key_string(privkey)
    pubkeystring = generateKeys.generate_public_key_string(privkey)
    
    newUser = User(
        username = newUserName,
        private_key = privkeystring,
        public_key = pubkeystring
    )

    
    newUser.set_password(data.get('password'))
    
    return jsonify({'userId': newUser.id, 'public_key':newUser.public_key}), 200

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
        cipheredText = request.args.get('ciphered')
        if not cipheredText:
             return jsonify({'error': 'Authentication error'}), 403
        user_id = request.args.get('userId')
        user = User.get_by_id(user_id)
        if not user:
            return jsonify({'error': 'Authentication error'}), 403
        public_key_pem = user.public_key.strip()
        public_key_pem = clean_pem(public_key_pem)
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),  # Ensure it's bytes
            backend=default_backend()
        )
        print('4', file=sys.stderr)
        # Decode the Base64-encoded ciphered text
        ciphered_bytes = base64.b64decode(cipheredText)
        print('5', file=sys.stderr)
        # Decrypt the ciphered text using the public key
        decrypted_text = public_key.decrypt(
            ciphered_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(decrypted_text, file=sys.stderr)
        if decrypted_text != "somerandomtext":
            return jsonify({'error': 'Authentication error'}), 403
            
        print(f'userId: {user_id}', file=sys.stderr)
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
        print(f'error: {e}', file=sys.stderr)
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500
def clean_pem(pem_string):
    # Remove headers and footers
    base64_data = re.sub(r'[-]+[A-Za-z0-9\s]+[-]+', '', pem_string).strip()
    
    # Remove all non-Base64 characters (e.g., spaces)
    cleaned_base64 = re.sub(r'[^A-Za-z0-9+/=]', '', base64_data)
    
    # Re-wrap the Base64 data into lines of 64 characters
    wrapped_base64 = '\n'.join([cleaned_base64[i:i+64] for i in range(0, len(cleaned_base64), 64)])
    
    # Reconstruct the PEM string
    return f"-----BEGIN PUBLIC KEY-----\n{wrapped_base64}\n-----END PUBLIC KEY-----"
    