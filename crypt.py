"""Модуль шифрования AES-256-CBC."""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii


def generate_key() -> bytes:
    """
    Генерирует случайный AES-256 ключ.

    Returns:
        32 байта (256 бит) случайных данных
    """
    return get_random_bytes(32)


def key_from_hex(hex_key: str) -> bytes:
    """
    Преобразует hex-строку в bytes ключ.

    Args:
        hex_key: 64 hex-символа

    Returns:
        32 байта ключа

    Raises:
        ValueError: если длина не 64 или неверный формат
    """
    if len(hex_key) != 64:
        raise ValueError("Ключ должен быть 64 hex символа")
    try:
        return binascii.unhexlify(hex_key)
    except binascii.Error as error:
        raise ValueError("Неверный формат ключа") from error


def encrypt(data: bytes, key: bytes) -> bytes:
    """
    Шифрует данные алгоритмом AES-256-CBC.

    Args:
        data: исходные байты
        key: 32-байтовый ключ

    Returns:
        IV (16 байт) + зашифрованные данные
    """
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, AES.block_size))


def decrypt(data: bytes, key: bytes) -> bytes:
    """
    Расшифровывает данные алгоритмом AES-256-CBC.

    Args:
        data: IV (16 байт) + зашифрованные данные
        key: 32-байтовый ключ

    Returns:
        Расшифрованные байты
    """
    initialization_vector = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=initialization_vector)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)