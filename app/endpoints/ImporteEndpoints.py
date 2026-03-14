from flask import Blueprint
from models.Importe import Importe
from repositories.ImporteRepository import ImporteRepository
from repositories.SeasonRepository import SeasonRepository
from endpoints.middlewares.AuthMiddleware import cryptography_required, signature_required, cipher_and_sign_response
from utils.ResponseMaker import make_response
from utils.Constants import Messages, ImporteMessages, SeasonMessages
from exceptions.Http import HttpException
from validators.FieldValidator import is_empty

importe_bp = Blueprint('importe', __name__)

@importe_bp.route('/api/v1/Importe/season', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def get_by_season(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["seasonId"])
        importes = ImporteRepository.get_by_season_id(decrypted_data.get('seasonId'), session)
        response = make_response(importes, True, ImporteMessages.FETCHED_PLURAL), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@importe_bp.route('/api/v1/Importe/id', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def get_by_id(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["id"])
        importe = ImporteRepository.get_by_id(decrypted_data.get('id'), session)
        if not importe:
            return make_response(None, False, ImporteMessages.NOT_FOUND), 200
        response = make_response(importe, True, ImporteMessages.FETCHED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@importe_bp.route('/api/v1/Importe/', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def create_importe(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["concept", "importeDate", "amount", "seasonId"])

        season = SeasonRepository.get_by_id(decrypted_data.get('seasonId'), session)
        if not season:
            return make_response(None, False, SeasonMessages.NOT_FOUND), 200

        new_importe = Importe(
            concept=decrypted_data.get('concept'),
            importeDate=decrypted_data.get('importeDate'),
            amount=decrypted_data.get('amount'),
            balanceAfter=decrypted_data.get('balanceAfter'),
            iban=decrypted_data.get('iban'),
            seasonId=decrypted_data.get('seasonId')
        )
        new_importe.save(session)
        response = make_response(new_importe, True, ImporteMessages.CREATED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@importe_bp.route('/api/v1/Importe/delete', methods=['POST'])
@cryptography_required
def delete_by_id(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["id"])
        ImporteRepository.delete_by_id(decrypted_data.get('id'), session)
        response = make_response(None, True, ImporteMessages.DELETED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500

@importe_bp.route('/api/v1/Importe/season/delete', methods=['POST'])
@cryptography_required
def delete_by_season(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["seasonId"])
        ImporteRepository.delete_by_season_id(decrypted_data.get('seasonId'), session)
        response = make_response(None, True, ImporteMessages.DELETED_PLURAL), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
