from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends.openssl.rsa import InvalidSignature
from hashlib import sha512


def get_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return (private_key, public_key)



def public_to_str(public_key):
    return  public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def str_to_public(str_public):
    return serialization.load_pem_public_key(
        str_public,
        backend=default_backend()
    )

def encrypt(message, public_key):
    try:
        message = message.encode()
    except:
        pass
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt(encrypted, private_key):
    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def sign(message, private_key):
    return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

def check(sign_message, message, public_key):
    try:
        public_key.verify(
            sign_message,
            message,
           padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
           ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def six(string):
    while len(string) < 6:
        string = "0" + string
    return string

def generate_code(public_key):
    return  sha512(public_to_str(public_key)).hexdigest()[:6].encode()

def verify_code(code, public_key):
    return generate_code(public_key) == code
