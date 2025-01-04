
import datetime
from flask import request, jsonify, make_response, current_app, redirect, url_for
import jwt
from . import auth_bp
import jwt
from .User import User

def token_required(f):
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'error': 'token is missing'}), 403
        try:
            jwt.decode(token, current_app.config['secret_key'], algorithms="HS256")
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'error': 'token is invalid'}), 403
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__  # Ensure Flask recognizes the wrapped function
    return decorated

@auth_bp.route("/login")
def login():
    
    auth = request.authorization
    if auth:
        
        user = User.query.filter(User.username == auth.username).first()
        
        if user is None:
            return make_response('User not found', 404, {'WWW-Authenticate': 'Basic realm="User Not Found"'})
        if(user.CorrectPassword(auth.password)):
            token = jwt.encode({'user': auth.username, 'exp': datetime.datetime.utcnow(
            ) + datetime.timedelta(seconds=10)}, current_app.config['secret_key'])
            return redirect(url_for('expenses.get_by_user', userId=user.id, token=token))
        else:
            return make_response('User not found', 404, {'WWW-Authenticate': 'Basic realm="User Not Found"'})

    return make_response('Could not Verify', 401, {'WWW-Authenticate': 'Basic realm ="Login Required"'})
        
    