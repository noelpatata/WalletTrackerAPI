from flask import jsonify
from utils.Logger import AppLogger
from utils.Constants import Messages
import traceback

class Response:
    def __init__(self, data=None, success=True, message=""):
        self.success = success
        self.message = message
        self.data = data

    def to_dict(self):
        if isinstance(self.data, list):
            data_value = [
                item.to_json_dict() if hasattr(item, "to_json_dict") else item
                for item in self.data
            ]
        else:
            data_value = self.data.to_json_dict() if self.data is not None and hasattr(self.data, "to_json_dict") else self.data
        return {
            "success": self.success,
            "message": self.message,
            "data": data_value
        }

def make_response(data=None, success=True, message="", exception=None, debug=False):
    try:
        log_message = message
        if success:
            AppLogger.info(message)
        else:
            if exception is not None:
                stack_trace = traceback.format_exc()
                exc_message = f"{str(exception)}"
                if debug:
                    log_message += f" [ INNER EXCEPTION ]: {exc_message}\n{stack_trace}"
                else:
                    log_message += f" [ INNER EXCEPTION ]: {exc_message}"
                AppLogger._logger.error(log_message, exc_info=exception)
            else:
                AppLogger.error(log_message)
        return jsonify(Response(data if data is not None else None, success, message).to_dict())
    except Exception as e:
        AppLogger._logger.error(str(e), exc_info=e)
        return jsonify({
            "success": False,
            "message": Messages.INTERNAL_ERROR,
            "data": None
        }), 500
