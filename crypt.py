from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii


def generate_key() -> bytes:
    """Генерирует случайный AES-256 ключ (32 байта)"""
    return get_random_bytes(32)


def key_from_hex(hex_key: str) -> bytes:
    """Преобразует hex-строку в bytes ключ. Проверяет длину и формат."""
    if len(hex_key) != 64:
        raise ValueError("Ключ должен быть 64 hex символа")
    try:
        return binascii.unhexlify(hex_key)
    except binascii.Error:
        raise ValueError("Неверный формат ключа")


def encrypt(data: bytes, key: bytes) -> bytes:
    """Возвращает IV + зашифрованные данные"""
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, AES.block_size))


def decrypt(data: bytes, key: bytes) -> bytes:
    """Принимает IV + зашифрованные данные"""
    iv, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)