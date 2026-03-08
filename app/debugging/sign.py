import base64
from utils.Cryptography import sign

with open("debugging/testing/private_key.pem", "rb") as f:
    private_key_bytes = f.read()

private_key_pem = base64.b64encode(private_key_bytes)

signature = sign(private_key_pem)
print("Here's your signature:\n"+signature)
