"""
Утилиты шифрования для MVP сервера
Стратегия: "Сервер ничего не знает о вас!"

Все чувствительные данные шифруются ключом сервера (AES-256-GCM)
"""
import os
import base64
import secrets
import logging
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


logger = logging.getLogger(__name__)


def get_encryption_key() -> bytes:
    """Получить ключ шифрования из переменных окружения"""
    key_str = os.getenv('ENCRYPTION_KEY_STR')
    if not key_str:
        raise ValueError("ENCRYPTION_KEY_STR не задан в env vars!")
    key = base64.urlsafe_b64decode(key_str)
    if len(key) != 32:
        raise ValueError("Неверный размер ключа шифрования! Должен быть 32 байта.")
    return key


def encrypt_data(data: str, key: Optional[bytes] = None) -> Optional[str]:
    """
    Шифрует данные с помощью AES-256-GCM
    
    Args:
        data: Строка для шифрования
        key: Опциональный ключ (по умолчанию из env)
    
    Returns:
        Base64-encoded строка: nonce[12] + ciphertext + tag[16]
        None в случае ошибки
    """
    if data is None:
        return None
    
    try:
        if key is None:
            key = get_encryption_key()
        
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        
        # Формат: nonce + ciphertext + tag
        encrypted = nonce + ciphertext + encryptor.tag
        return base64.urlsafe_b64encode(encrypted).decode()
    except Exception as e:
        logger.error(f"Ошибка шифрования данных: {str(e)}")
        return None


def decrypt_data(enc_data: str, key: Optional[bytes] = None) -> Optional[str]:
    """
    Расшифровывает данные, зашифрованные с помощью AES-256-GCM
    
    Args:
        enc_data: Base64-encoded зашифрованная строка
        key: Опциональный ключ (по умолчанию из env)
    
    Returns:
        Расшифрованная строка
        None в случае ошибки
    """
    if enc_data is None:
        return None
    
    try:
        if key is None:
            key = get_encryption_key()
        
        encrypted_bytes = base64.urlsafe_b64decode(enc_data)
        if len(encrypted_bytes) < 12 + 16:
            raise ValueError("Данные слишком короткие для расшифровки")
        
        nonce = encrypted_bytes[:12]
        tag = encrypted_bytes[-16:]
        ciphertext = encrypted_bytes[12:-16]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode()
    except Exception as e:
        logger.error(f"Ошибка расшифровки данных: {str(e)}")
        return None


def encrypt_datetime(dt) -> Optional[str]:
    """
    Шифрует datetime объект как ISO строку
    
    Args:
        dt: datetime объект
    
    Returns:
        Зашифрованная строка
    """
    if dt is None:
        return None
    
    try:
        iso_str = dt.isoformat()
        return encrypt_data(iso_str)
    except Exception as e:
        logger.error(f"Ошибка шифрования datetime: {str(e)}")
        return None


def decrypt_datetime(enc_data: str):
    """
    Расшифровывает datetime из зашифрованной ISO строки
    
    Args:
        enc_data: Зашифрованная строка
    
    Returns:
        datetime объект или None
    """
    if enc_data is None:
        return None
    
    try:
        from datetime import datetime
        iso_str = decrypt_data(enc_data)
        if iso_str:
            return datetime.fromisoformat(iso_str)
        return None
    except Exception as e:
        logger.error(f"Ошибка расшифровки datetime: {str(e)}")
        return None


def encrypt_int(value: int) -> Optional[str]:
    """Шифрует целое число как строку"""
    if value is None:
        return None
    return encrypt_data(str(value))


def decrypt_int(enc_data: str) -> Optional[int]:
    """Расшифровывает целое число из зашифрованной строки"""
    if enc_data is None:
        return None
    
    try:
        decrypted = decrypt_data(enc_data)
        if decrypted:
            return int(decrypted)
        return None
    except Exception as e:
        logger.error(f"Ошибка расшифровки int: {str(e)}")
        return None


def encrypt_json(data: dict) -> Optional[str]:
    """Шифрует JSON объект"""
    if data is None:
        return None
    
    try:
        import json
        json_str = json.dumps(data)
        return encrypt_data(json_str)
    except Exception as e:
        logger.error(f"Ошибка шифрования JSON: {str(e)}")
        return None


def decrypt_json(enc_data: str) -> Optional[dict]:
    """Расшифровывает JSON объект"""
    if enc_data is None:
        return None
    
    try:
        import json
        json_str = decrypt_data(enc_data)
        if json_str:
            return json.loads(json_str)
        return None
    except Exception as e:
        logger.error(f"Ошибка расшифровки JSON: {str(e)}")
        return None
