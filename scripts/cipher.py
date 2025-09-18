import sys
import base64
from utils.cryptography import hybrid_ecryption_with_public_key

with open("testing/public_key.pem", "rb") as f:
    public_key_bytes = f.read()

json = sys.argv[1]
if not json:
    sys.exit()

public_key_pem = base64.b64encode(public_key_bytes)
ciphered_text = hybrid_ecryption_with_public_key(json, public_key_pem)
print(ciphered_text)





