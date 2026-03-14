from flask import Blueprint
from models.Season import Season
from repositories.SeasonRepository import SeasonRepository
from endpoints.middlewares.AuthMiddleware import cryptography_required, signature_required, cipher_and_sign_response
from utils.ResponseMaker import make_response
from utils.Constants import Messages, SeasonMessages
from exceptions.Http import HttpException
from validators.FieldValidator import is_empty

season_bp = Blueprint('season', __name__)

@season_bp.route('/api/v1/Season/all', methods=['GET'])
@signature_required
@cipher_and_sign_response
def get_all(user_id, session, user):
    try:
        seasons = SeasonRepository.get_all(session)
        response = make_response(seasons, True, SeasonMessages.FETCHED_PLURAL), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@season_bp.route('/api/v1/Season/id', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def get_by_id(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["id"])
        season = SeasonRepository.get_by_id(decrypted_data.get('id'), session)
        if not season:
            return make_response(None, False, SeasonMessages.NOT_FOUND), 200
        response = make_response(season, True, SeasonMessages.FETCHED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@season_bp.route('/api/v1/Season/', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def get_or_create(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["year", "month"])
        year = decrypted_data.get('year')
        month = decrypted_data.get('month')
        season = SeasonRepository.get_or_create(year, month, session)
        response = make_response(season, True, SeasonMessages.FETCHED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@season_bp.route('/api/v1/Season/delete', methods=['POST'])
@cryptography_required
def delete_by_id(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["id"])
        SeasonRepository.delete_by_id(decrypted_data.get('id'), session)
        response = make_response(None, True, SeasonMessages.DELETED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
