import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

default_key_file = os.environ.get("KEYFILE")


def generate_save_key(pass_phrase, file_name):
    password = pass_phrase.encode()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64decode(kdf.derive(password))
    with open(file_name, "wb") as fh:
        fh.write(key)


def encrypt_data(msg, key_file=default_key_file):
    key = open(key_file, "rb").read()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(msg.encode())
    return encrypted_message.decode()


def decrypt_data(msg, key_file=default_key_file):
    key = open(key_file, "rb").read()
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(msg.encode())
    return decrypted_message.decode()

