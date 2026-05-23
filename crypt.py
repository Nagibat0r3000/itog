from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_key() -> bytes:
    return get_random_bytes(32)  # AES-256


def encrypt(data: bytes, key: bytes) -> bytes:
    """Возвращает IV + зашифрованные данные."""
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, AES.block_size))


def decrypt(data: bytes, key: bytes) -> bytes:
    """Принимает IV + зашифрованные данные."""
    iv, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
