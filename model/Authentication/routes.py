from functools import wraps
import json
import base64
import os
import utils.generateKeys as generateKeys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import datetime
from flask import Response, request, jsonify, make_response, current_app
import jwt
from . import auth_bp
from .User import User
from constants import TokenErrors

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        cipher_header = request.headers.get('Cipher')
        auth_header = request.headers.get('Authorization')
        encrypted_data = request.get_json(silent = True)
        if not cipher_header or not auth_header:
            return jsonify({'error': 'Authentication error'}), 403

        
        if not auth_header.startswith("Bearer "):
            return jsonify({'error': 'Invalid Authorization header format. Use Bearer <token>'}), 403

        cipheredTextb64 = cipher_header
        token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'error': TokenErrors.missing}), 403
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
          
            if not public_key_pem:
                return jsonify({'success': False, 'message': 'Invalid data'}), 403

            public_key = serialization.load_pem_public_key(
                public_key_pem
            )

            try:
                signature_bytes = base64.b64decode(cipheredTextb64)
            except Exception as e:
                return jsonify({'success': False, 'message': 'Invalid data'}), 403
            except Exception as e:
                return jsonify({'success': False, 'message': f'Invalid data'}), 403
            
            public_key.verify(
                signature_bytes,
                b"s0m3r4nd0mt3xt",
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            if encrypted_data:
                decrypted_data = decrypt_with_private_key(encrypted_data, user.private_key)
                if not decrypted_data or not isinstance(decrypted_data, dict):
                    return jsonify({'success': False, 'message': f'Invalid data'}), 403
            else: 
                decrypted_data = ''
                
            
            kwargs['userId'] = userId_from_payload
            kwargs['decrypted_data'] = decrypted_data
        except jwt.ExpiredSignatureError:
            return jsonify({'error': TokenErrors.expired}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': TokenErrors.invalid}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def encrypt_with_public_key(data, public_key_str):
    # Load RSA public key
    decoded_pem = base64.b64decode(public_key_str).decode()
    public_key = serialization.load_pem_public_key(decoded_pem.encode(), backend=default_backend())

    # 🔹 Generate a random AES key (32 bytes for AES-256)
    aes_key = os.urandom(32)
    
    # 🔹 Generate a random IV (initialization vector) for AES-GCM
    iv = os.urandom(12)

    # 🔹 Encrypt the data using AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()

    # 🔹 Encrypt the AES key using RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 🔹 Return both encrypted AES key + encrypted data, base64 encoded
    return {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode()  # Authentication tag for AES-GCM
    }
def decrypt_with_private_key(encrypted_data, private_key_str):
    try:
        # Load RSA private key
        private_key = serialization.load_pem_private_key(
            base64.b64decode(private_key_str), password=None, backend=default_backend()
        )

        # Decode base64-encoded values
        encrypted_aes_key = base64.b64decode(encrypted_data["encrypted_aes_key"])
        iv = base64.b64decode(encrypted_data["iv"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])

        # Decrypt the AES key using the RSA private key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the ciphertext using AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        return json.loads(decrypted_data.decode())
    except Exception as e:
        return {"success": False, "message": f"Decryption failed: {str(e)}"}

# Helper function to sign data with the user's private key
def sign_with_private_key(data, private_key_str):
    private_key = serialization.load_pem_private_key(base64.b64decode(private_key_str), password=None, backend=default_backend())
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

# Middleware to intercept requests and responses
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

                    signature = sign_with_private_key("s0m3r4nd0mt3xt", user.private_key)
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


'''
@auth_bp.route("/register/", methods=['POST'])
def register():
    
    # validation
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    
    newUserName = data.get('username')
    if not newUserName or newUserName == "":
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    
    if User.check_exists(newUserName):
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    
    #user creation   
    privkey = generateKeys.generate_private_key() 
    privkeystring = generateKeys.generate_private_key_string(privkey)
    pubkeystring = generateKeys.generate_public_key_string(privkey)
    
    newUser = User(
        username = newUserName,
        private_key = privkeystring,
        public_key = pubkeystring,
        client_public_key = ""
    )

    
    newUser.set_password(data.get('password'))
    
    return jsonify({'userId': newUser.id, 'public_key':newUser.public_key}), 200 '''

@auth_bp.route("/login/", methods=['POST'])
def login():
    try:
        auth = request.get_json() # get basic auth credentials
        if auth:
            user = User.query.filter(User.username == auth.get('username')).first()
            
            if user is None:
                return jsonify({'success': False, 'message': 'Invalid data'}), 403
            if(user.CorrectPassword(auth.get('password'))):
                payload = {'user': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)}
                token = jwt.encode(
                    payload,
                    current_app.config['PRIVATE_KEY'],
                    algorithm='RS256')
                return jsonify({'token': token}), 200
            else:
                return make_response('User not found', 404, {'WWW-Authenticate': 'Basic realm="User Not Found"'})

        return make_response('Could not Verify', 401, {'WWW-Authenticate': 'Basic realm ="Login Required"'})
    except Exception as e:
        return make_response('User not found', 404, {'WWW-Authenticate': 'Basic realm="User Not Found"'})

    

@auth_bp.route("/autologin/", methods=['POST'])
def autologin():
    try:
        data = request.get_json() # get json data from body
        if not data or 'userId' not in data or 'ciphered' not in data:
            return jsonify({'success': False, 'message': 'Invalid data'}), 403

        user_id = data.get('userId')
        ciphered_textbs64 = data.get('ciphered')

        if not user_id or not ciphered_textbs64:
            return jsonify({'success': False, 'message': 'Invalid data'}), 403

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'success': False, 'message': 'Invalid data'}), 403

        # Load the private key (assuming it's stored securely in the user object)
        public_key_pem = base64.b64decode(user.client_public_key)
          # Ensure no extra whitespace
        if not public_key_pem:
            return jsonify({'success': False, 'message': 'Invalid data'}), 403

            # Deserialize the private key
        public_key = serialization.load_pem_public_key(
            public_key_pem
        )

            # Decode the Base64-encoded ciphered text
        try:
            signature_bytes = base64.b64decode(ciphered_textbs64)
        except Exception as e:
            return jsonify({'success': False, 'message': 'Invalid data5'}), 403
        except Exception as e:
            return jsonify({'success': False, 'message': f'Invalid data6'}), 403
            
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
        return jsonify({'success': False, 'message': f'{e}'}), 403
@auth_bp.route("/getUserServerPubKey/", methods=['POST'])
def get_user_pub_key():
    
    data = request.get_json()

    if not data:
        return jsonify({'success': False, 'message': 'Invalid data'}), 403

    
    username = data.get('username')
    password = data.get('password')

    if not username or username == "":
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    if not password or password == "":
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    
    user = User.query.filter(User.username == username).first()
    if not user:
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    if(not user.CorrectPassword(password)):
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    
    return jsonify({'userId': user.id, 'publicKey':user.public_key}), 200

@auth_bp.route("/setUserClientPubKey/", methods=['POST'])
def set_user_pub_key():
    
    # validation
    data = request.get_json()

    if not data:
        return jsonify({'success': False, 'message': 'Invalid data'}), 403

    pub_key_b64 = data.get('publicKey')
    if not pub_key_b64:
        return jsonify({'success': False, 'message': 'Invalid data'}), 403

    
    username = data.get('username')
    password = data.get('password')
    if not username or username == "":
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    if not password or password == "":
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    
    user = User.query.filter(User.username == username).first()
    if not user:
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    if(not user.CorrectPassword(password)):
        return jsonify({'success': False, 'message': 'Invalid data'}), 403
    user.client_public_key = pub_key_b64
    user.save()
    return jsonify({'success': True, 'message':'Public key sent successfully'}), 200
    