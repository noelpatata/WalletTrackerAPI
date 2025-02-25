from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

# Assuming the public key is base64 encoded in the database:
base64_public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq7a8bNUaGl42FzzxZctTKUH/litiI5a/W24THi3CUxebmUHqv22jO3589egwiViGtBslb+IzAxFOc5FgYw3AFHgSpKVoQWMdOU/voBue9+l3IvMGH5QiZugKZcrGLbUPUvBTo0KVi/5q3nQMVor5nD03SDuYlhP8p/hu0Ehvc4wLFh9oChufNltDGeB7Pn/qsTP5ohSWhJJYufdu+kO98dEMjRJAofvXb4HmBFCazYfBrrbmTOJVBFaOBynz9mHmZiANRfvZeq9BvQYcYDoHr+f/dmvkjtXLbuJUkqoimqqVSn/mwIyaSk079QNTlfFU8MRVG7+Z5ksMsecYygl4zwIDAQAB"

# Step 1: Decode the Base64 public key to get the raw key bytes
public_key_bytes = base64.b64decode(base64_public_key)

# Step 2: Wrap the public key in PEM format
pem_public_key = b"-----BEGIN PUBLIC KEY-----\n"
pem_public_key += base64.b64encode(public_key_bytes)  # Base64 encode again to ensure formatting
pem_public_key += b"\n-----END PUBLIC KEY-----"

# Step 3: Load the public key from the PEM format
public_key = serialization.load_pem_public_key(pem_public_key)

# Example of how to verify the signature
signature_bytes = base64.b64decode("your_base64_encoded_signature_here")
data_to_verify = b"s0m3r4nd0mt3xt"

# Step 4: Verify the signature
public_key.verify(
    signature_bytes,
    data_to_verify,
    padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
