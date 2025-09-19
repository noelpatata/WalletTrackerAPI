import sys
import base64
import requests

with open("testing/public_key.pem", "rb") as f:
    public_key_bytes = f.read()

token = sys.argv[1]
if not token:
    sys.exit()

public_key_pem = base64.b64encode(public_key_bytes).decode("utf-8")
print(public_key_pem)

url = "http://localhost:8080/setUserClientPubKey"
headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer YOUR_JWT_TOKEN_HERE"
}
data = {
    "publicKey": public_key_pem
}

response = requests.post(url, json=data, headers=headers)