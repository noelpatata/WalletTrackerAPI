import os
import base64
import json
import jwt
from flask import current_app
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from config import SECRET
from utils.constants import TokenMessages, AuthMessages
from utils.responseMaker import make_response
from exceptions.HttpException import HttpError

def generate_private_key():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        raise HttpError(AuthMessages.PRIVATE_KEY_FAILED, 401, e)
    

def generate_private_key_string(private_key):
    try:
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return base64.b64encode(private_bytes).decode()
    except Exception as e:
        raise HttpError(AuthMessages.PRIVATE_KEY_FAILED, 401, e)
    
    

def generate_public_key_string(private_key):
    try:
        public_key = private_key.public_key()
        public_key_bytes =  public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
        return base64.b64encode(public_key_bytes).decode()
    except Exception as e:
        raise HttpError(AuthMessages.PUBLIC_KEY_FAILED, 401, e)
    

def generate_keys_file(relativeFolder=""):

    try:
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
    except Exception as e:
        raise HttpError(AuthMessages.PAIRED_KEYS_FAILED, 401, e)
    
    
    

def hybrid_decryption(encrypted_data, private_key_str):
    try:
        if not encrypted_data:
            return make_response(None, False, AuthMessages.INVALID_PAYLOAD), 401
        
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
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_text = decrypted_bytes.decode("utf-8")
        decrypted_json = json.loads(decrypted_text)
        
        return decrypted_json
    except Exception as e:
        raise HttpError(AuthMessages.DECRYPTION_FAILED, 401, e)

def hybrid_encryption(data, public_key_pem):

    try:

        aes_key = os.urandom(32)
        iv = os.urandom(12)

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode("utf-8")) + encryptor.finalize()
        tag = encryptor.tag

        public_key = serialization.load_pem_public_key(base64.b64decode(public_key_pem), backend=default_backend())

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
    except Exception as e:
        raise HttpError(AuthMessages.ENCRYPTION_FAILED, 401, e)
    
def sign(data, private_key_pem):
    try:
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
    except Exception as e:
        raise HttpError(AuthMessages.SIGNATURE_FAILED, 401, e)
    
    

def verify_signature(public_key_pem, signed_text_bs64):
    try:
        if not signed_text_bs64:
            return make_response(None, False, AuthMessages.INVALID_HEADERS), 415
        
        public_key = serialization.load_pem_public_key(
            base64.b64decode(public_key_pem)
        )
        signature_bytes = base64.b64decode(signed_text_bs64)
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
        raise HttpError(AuthMessages.VERIFICATION_FAILED, 401, e)
            
def decode_jwt(token):
    try:
        payload = jwt.decode(
                token,
                current_app.config['PUBLIC_KEY'],
                algorithms=['RS256']
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HttpError(TokenMessages.EXPIRED, 401)
    except jwt.InvalidTokenError:
        raise HttpError(TokenMessages.INVALID, 401)
    