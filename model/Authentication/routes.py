from __future__ import print_function # In python 2.7
import sys

import datetime
from flask import request, jsonify, make_response, current_app, redirect, url_for
import jwt
from . import auth_bp
from .User import User
from strings import Errors

def ExpenseCategoryToken_required(f):
    def decorated(*args, **kwargs):
        print(args, file=sys.stderr)
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header is missing'}), 403

        if not auth_header.startswith("Bearer "):
            return jsonify({'error': 'Invalid Authorization header format. Use Bearer <token>'}), 403

        token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'error': Errors.missing}), 403
        try:
            payload = jwt.decode(token, current_app.config['PUBLIC_KEY'], algorithms="RS256")
            userId_from_url = kwargs.get('userId')
            if userId_from_url != payload.get('user'):
                return jsonify({'error': 'User ID missing from token'}), 403
            if not userId_from_url:
                return jsonify({'error': 'User ID missing from token'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'error': Errors.expired}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': Errors.invalid}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def token_required(f):
    def decorated(*args, **kwargs):
        print(args, file=sys.stderr)
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header is missing'}), 403

        if not auth_header.startswith("Bearer "):
            return jsonify({'error': 'Invalid Authorization header format. Use Bearer <token>'}), 403

        token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'error': Errors.missing}), 403
        try:
            jwt.decode(token, current_app.config['PUBLIC_KEY'], algorithms="RS256")
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
            return jsonify({'token': token}), 200
        else:
            return make_response('User not found', 404, {'WWW-Authenticate': 'Basic realm="User Not Found"'})

    return make_response('Could not Verify', 401, {'WWW-Authenticate': 'Basic realm ="Login Required"'})
        
    