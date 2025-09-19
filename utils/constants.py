class Messages:
    INTERNAL_ERROR = "Internal server error"
    INVALID_REQUEST = "Invalid request"
class UserMessages:
    CREATED = "User created successfully"
    USER_NOT_FOUND = "User not found"
class TokenMessages:
    MISSING = "Missing token"
    EXPIRED = "Expired token"
    INVALID = "Invalid token"
class AuthMessages:
    AUTH_ERROR = "Authorization error"
    LOGGED_IN = "Logged in successfully"
    FETCHED_SERVER_PUB_KEY = "Fetched server's public key successfully"
    ASSIGNED_SERVER_CLIENT_KEY = "Assigned client's public key successfully"
    ALREADY_EXISTS = "User already exists"
    DECRYPTION_FAILED = "Decryption process failed"
    VERIFICATION_FAILED = "Signature verification process failed"
    INVALID_KEY = "Invalid key"
    INVALID_HEADERS = "Invalid headers"
    INVALID_PAYLOAD = "Invalid payload"
class ExpenseCategoryMessages:
    FETCHED = "ExpenseCategory fetched successfully"
    FETCHED_PLURAL = "ExpenseCategory's fetched successfully"
    CREATED = "ExpenseCategory created successfully"
    DELETED = "ExpenseCategory deleted successfully"
    MODIFIED = "ExpenseCategory modified successfully"
class ExpenseMessages:
    FETCHED = "Expense fetched successfully"
    FETCHED_PLURAL = "Expense's fetched successfully"
    CREATED = "Expense created successfully"
    DELETED = "Expense deleted successfully"
    MODIFIED = "Expense modified successfully"