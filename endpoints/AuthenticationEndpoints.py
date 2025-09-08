import os
import datetime
import base64
import json
import jwt
from flask import Blueprint, Response, request, jsonify, current_app
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from config import SECRET
from utils.generateKeys import generate_private_key, generate_private_key_string, generate_public_key_string
from utils.constants import  Messages, AuthMessages, TokenMessages, UserMessages
from utils.multitenant import create_tenant_user_and_db
from utils.responseMaker import make_response
from repositories.UserRepository import User

auth_bp = Blueprint('authentication', __name__)

@auth_bp.route("/login/", methods=['POST'])
def login():
    try:
        auth = request.get_json()
        if auth:
            user = User.query.filter(User.username == auth.get('username')).first()
            
            if user is None:
                return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
            if(user.CorrectPassword(auth.get('password'))):
                payload = {'user': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)}
                token = jwt.encode(
                    payload,
                    current_app.config['PRIVATE_KEY'],
                    algorithm='RS256')
                return make_response({'token': token}, True, AuthMessages.LOGGED_IN_SUCCESSFULLY), 200
            else:
                return make_response(None, False, UserMessages.USER_NOT_FOUND), 404

        return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    
@auth_bp.route("/register/", methods=['POST'])
def register():
    
    data = request.get_json()
    if not data:
        return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
    
    new_username = data.get('username')
    if not new_username or new_username == "":
        return make_response(None, False, AuthMessages.INVALID_REQUEST), 200
    
    if User.check_exists(new_username):
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

    except Exception as db_exc:
        new_user.delete()
        return make_response(None, False, Messages.INTERNAL_ERROR), 500
    return make_response(new_user, True, UserMessages.CREATED_SUCCESSFULLY)

@auth_bp.route("/autoLogin/", methods=['POST'])
def autologin():
    try:
        data = request.get_json()
        if not data or 'userId' not in data or 'ciphered' not in data:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200

        user_id = data.get('userId')
        ciphered_textbs64 = data.get('ciphered')

        if not user_id or not ciphered_textbs64:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200

        public_key_pem = base64.b64decode(user.client_public_key)
        
        if not public_key_pem:
            return make_response(None, False, AuthMessages.INVALID_REQUEST), 200

        public_key = serialization.load_pem_public_key(
            public_key_pem
        )

        try:
            signature_bytes = base64.b64decode(ciphered_textbs64)
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

        payload = {
            'user': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        }
        token = jwt.encode(
            payload,
            current_app.config['PRIVATE_KEY'],
            algorithm='RS256'
        )

        return make_response({'userId': user.id, 'token': token}, True, AuthMessages.LOGGED_IN_SUCCESSFULLY), 200
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR), 500

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
    