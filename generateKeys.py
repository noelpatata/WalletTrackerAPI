from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_private_key():
    # TODO
    # Hay que devolver un array con clave privada y publica, y guardar en base de datos texto, actualmente se guarda el objeto
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return  private_key

def generate_private_key_string(private_key):
    # TODO
    # Hay que devolver un array con clave privada y publica, y guardar en base de datos texto, actualmente se guarda el objeto
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return  private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
        )   
    

def generate_public_key_string(private_key):
    public_key = private_key.public_key()
    return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

def generate_keys_file():
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize and save the private key
    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Generate corresponding public key
    public_key = private_key.public_key()

    # Serialize and save the public key
    with open("public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("Keys generated successfully:")
    print("- private_key.pem")
    print("- public_key.pem")

if __name__ == "__main__":
    generate_keys_file()
