import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Decode the public key from base64
public_key_b64 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxWFJXejJ0ZVM2VjdNQWdBTWc5YwpveWg5cHdnZVFjZXRCM0JLeFRQbGJHVlRGb0dpUEVaS0R5ZzFUbUNYZDYySEl3NWlQWDMwbTV2YThLdWcwZUtZCnJFNFQ5QnduS2tXbzZaQTBTT1VHTEt2WG1nOHZFcWJqQ1JYSmt2cXdiMWN5QloxWWtNeThwWmJFWHhpYUZUZ0EKY3BPU2dlUklOTTI2ZVBKaC9YUmZ6eXBPR1VKTmtZS0hIR0FLY0VZWTVLeFVCS21ORm5CZFBMY3M1czlGOUhEdgpIZFFxUnNsNnJ3MWRocFIxaHBES3ZVOVJjd1BmSWF6R3RRUmE3SURTM1l6OVJGNituRXRBUEhjdGhHVUg4Myt1ClJiUFJ5VEdCSXBUU0xDdlo5WWhsZzF4M3I3V25UY3Bnb3JGY2xENjBqYkNkOEZudkZmQUcvWWgwdDZHdVRkVHkKcVFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
public_key_pem = base64.b64decode(public_key_b64).decode()

# Load the public key
public_key = serialization.load_pem_public_key(public_key_pem.encode())

# Message to encrypt
message = b"s0m3r4nd0mt3xt"

# Encrypt the message
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Print the encrypted message in base64 format
ciphered_text_b64 = base64.b64encode(ciphertext).decode()
print("Ciphered Text:", ciphered_text_b64)


#how to decrypt:
"""
private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

try:
    ciphered_bytes = base64.b64decode(ciphered_text)
except Exception as e:
    return jsonify({'success': False, 'message': 'Invalid data'}), 203

try:
    decrypted_text = private_key.decrypt(
    ciphered_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)        # Decode the Base64-encoded ciphered text
"""