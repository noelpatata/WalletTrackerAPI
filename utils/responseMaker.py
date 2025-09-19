from flask import jsonify

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

    
def make_response(data=None, success=True, message="", exception=None):
    return jsonify(Response(data if data is not None else None, success, message).to_dict())

