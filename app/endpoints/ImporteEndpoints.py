from flask import Blueprint
from services.ImporteService import ImporteService
from endpoints.middlewares.AuthMiddleware import cryptography_required, signature_required, cipher_and_sign_response
from utils.ResponseMaker import make_response
from utils.Constants import Messages, ImporteMessages
from exceptions.Http import HttpException
from validators.FieldValidator import is_empty

importe_bp = Blueprint('importe', __name__)

@importe_bp.route('/api/v1/Importe/season', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def get_by_season(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["seasonId"])
        importes = ImporteService.get_by_season(decrypted_data.get('seasonId'), session)
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
        importe = ImporteService.get_by_id(decrypted_data.get('id'), session)
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
        importe = ImporteService.create(
            concept=decrypted_data.get('concept'),
            importe_date=decrypted_data.get('importeDate'),
            amount=decrypted_data.get('amount'),
            balance_after=decrypted_data.get('balanceAfter'),
            season_id=decrypted_data.get('seasonId'),
            session=session
        )
        response = make_response(importe, True, ImporteMessages.CREATED), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500


@importe_bp.route('/api/v1/Importe/all', methods=['POST'])
@cryptography_required
@cipher_and_sign_response
def create_importes_bulk(user_id, session, user, decrypted_data):
    try:
        is_empty(decrypted_data, ["importes"])
        importes_data = decrypted_data.get('importes')
        if not isinstance(importes_data, list) or len(importes_data) == 0:
            raise HttpException(Messages.INVALID_REQUEST, 400)

        for item in importes_data:
            is_empty(item, ["concept", "importeDate", "amount", "seasonId"])

        created = ImporteService.create_bulk(importes_data, session)
        response = make_response(created, True, ImporteMessages.CREATED_PLURAL), 200
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
        ImporteService.delete_by_id(decrypted_data.get('id'), session)
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
        ImporteService.delete_by_season(decrypted_data.get('seasonId'), session)
        response = make_response(None, True, ImporteMessages.DELETED_PLURAL), 200
        session.remove()
        return response
    except HttpException as e:
        return make_response(None, False, e.message, e.inner_exception), e.status_code
    except Exception as e:
        return make_response(None, False, Messages.INTERNAL_ERROR, e), 500
