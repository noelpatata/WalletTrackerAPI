import sys
import base64
import json
from utils.Cryptography import hybrid_encryption

with open("testing/server_public_key.pem", "rb") as f:
    public_key_bytes = f.read()

input_json = sys.argv[1]
if not input_json:
    sys.exit()

public_key_pem = base64.b64encode(public_key_bytes)
input_json_double_quotes = input_json.replace("'", '"')
ciphered_text = hybrid_encryption(input_json_double_quotes, public_key_pem)
ciphered_json = json.dumps(ciphered_text)
print(ciphered_json)





