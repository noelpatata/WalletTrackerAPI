class HttpException(Exception):
    def __init__(self, message, status_code=400, inner_exception=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.inner_exception = inner_exception
