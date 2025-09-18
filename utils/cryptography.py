import os
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from config import SECRET

def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def generate_private_key_string(private_key):
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(private_bytes).decode()
    

def generate_public_key_string(private_key):
    public_key = private_key.public_key()
    public_key_bytes =  public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    return base64.b64encode(public_key_bytes).decode()

def generate_keys_file(relativeFolder=""):
    
    destFolder = relativeFolder+"\\" if len(relativeFolder) > 0 else ""

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open(destFolder+"private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    public_key = private_key.public_key()

    with open(destFolder+"public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

def decrypt_with_private_key(encrypted_data, private_key_str):
    try:
        private_key = serialization.load_pem_private_key(
            base64.b64decode(private_key_str), password=None, backend=default_backend()
        )

        encrypted_aes_key = base64.b64decode(encrypted_data["encrypted_aes_key"])
        iv = base64.b64decode(encrypted_data["iv"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])

        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        return json.loads(decrypted_data.decode())
    except Exception as e:
        return str(e)

def hybrid_ecryption_with_public_key(data, public_key_pem):
    public_key = serialization.load_pem_public_key(base64.b64decode(public_key_pem), backend=default_backend())

    aes_key = os.urandom(32)
    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }


def encrypt_with_public_key(data, public_key_pem):
    decoded_pem = base64.b64decode(public_key_pem).decode()
    public_key = serialization.load_pem_public_key(decoded_pem.encode(), backend=default_backend())

    aes_key = os.urandom(32)
    
    iv = os.urandom(12)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode()
    }
    
def sign(data, private_key_pem):
    private_key = serialization.load_pem_private_key(base64.b64decode(private_key_pem), password=None, backend=default_backend())
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(public_key_pem, ciphered_text_bs64):

    
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem
        )
        signature_bytes = base64.b64decode(ciphered_text_bs64)
        public_key.verify(
            signature_bytes,
            SECRET.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        return False
            
    