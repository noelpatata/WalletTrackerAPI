from flask import current_app
from datetime import datetime, timedelta, timezone
import jwt
from models.User import User
from repositories.UserRepository import UserRepository
from utils.Cryptography import generate_private_key, generate_private_key_string, generate_public_key_string
from utils.Multitenant import create_tenant_user_and_db
from exceptions.Http import HttpException
from utils.Constants import AuthMessages, UserMessages


class UserService:

    @staticmethod
    def login(username: str, password: str) -> str:
        user = UserRepository.get_by_username(username)
        if user is None or not UserRepository.check_password(user, password):
            raise HttpException(UserMessages.USER_NOT_FOUND, 401)

        payload = {
            'user': user.id,
            'exp': datetime.now(timezone.utc) + timedelta(minutes=5)
        }
        token = jwt.encode(payload, current_app.config['PRIVATE_KEY'], algorithm='RS256')
        return token

    @staticmethod
    def register(username: str, password: str) -> User:
        if UserRepository.exists(username):
            raise HttpException(AuthMessages.ALREADY_EXISTS, 200)

        private_key = generate_private_key()
        new_user = User(
            username=username,
            private_key=generate_private_key_string(private_key),
            public_key=generate_public_key_string(private_key),
            client_public_key=""
        )

        created_user = UserRepository.create_with_password(new_user, password)
        create_tenant_user_and_db(created_user)
        return created_user

    @staticmethod
    def get_by_id(user_id: int) -> User:
        user = UserRepository.get_by_id(user_id)
        if not user:
            raise HttpException(UserMessages.USER_NOT_FOUND, 404)
        return user

    @staticmethod
    def set_client_public_key(user_id: int, pub_key_b64: str) -> None:
        user = UserRepository.get_by_id(user_id)
        if not user:
            raise HttpException(UserMessages.USER_NOT_FOUND, 404)
        user.client_public_key = pub_key_b64
        user.save()
