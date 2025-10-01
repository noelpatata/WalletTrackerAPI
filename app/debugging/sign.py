import base64
from config import SECRET
from utils.Cryptography import sign

with open("testing/private_key.pem", "rb") as f:
    private_key_bytes = f.read()

private_key_pem = base64.b64encode(private_key_bytes)

signature = sign(SECRET, private_key_pem)
print("Here's your signature:\n"+signature)
