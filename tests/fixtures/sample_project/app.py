import hashlib
import hmac

from cryptography.fernet import Fernet


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_hmac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha1).hexdigest()


def encrypt_data(data: bytes) -> bytes:
    key = Fernet.generate_key()
    return Fernet(key).encrypt(data)
