"""
Обертки для работы с зашифрованными данными в Redis
Автоматически шифрует/расшифровывает данные при записи/чтении
"""
import json
import logging
from typing import Optional, Any
from app.encryption import encrypt_data, decrypt_data, encrypt_json, decrypt_json


logger = logging.getLogger(__name__)


class EncryptedRedisClient:
    """
    Обертка над Redis клиентом с автоматическим шифрованием
    для чувствительных данных
    """
    
    def __init__(self, redis_client):
        self.redis_client = redis_client
        # Паттерны ключей, которые требуют шифрования
        self.encrypted_patterns = [
            'csrf:',
            'device:',
            'push:',
        ]
    
    def _should_encrypt(self, key: str) -> bool:
        """Проверяет, нужно ли шифровать данный ключ"""
        return any(key.startswith(pattern) for pattern in self.encrypted_patterns)
    
    async def set(self, key: str, value: Any, ex: Optional[int] = None, **kwargs) -> bool:
        """
        Устанавливает значение с автоматическим шифрованием
        
        Args:
            key: Ключ Redis
            value: Значение (строка или dict)
            ex: Время жизни в секундах
            **kwargs: Дополнительные параметры для Redis
        
        Returns:
            True если успешно
        """
        if self._should_encrypt(key):
            # Шифруем значение
            if isinstance(value, dict):
                encrypted_value = encrypt_json(value)
            else:
                encrypted_value = encrypt_data(str(value))
            
            if encrypted_value is None:
                logger.error(f"Не удалось зашифровать значение для ключа {key}")
                return False
            
            return await self.redis_client.set(key, encrypted_value, ex=ex, **kwargs)
        else:
            # Обычная запись без шифрования
            if isinstance(value, dict):
                value = json.dumps(value)
            return await self.redis_client.set(key, value, ex=ex, **kwargs)
    
    async def get(self, key: str) -> Optional[str]:
        """
        Получает значение с автоматической расшифровкой
        
        Args:
            key: Ключ Redis
        
        Returns:
            Расшифрованное значение или None
        """
        value = await self.redis_client.get(key)
        
        if value is None:
            return None
        
        if self._should_encrypt(key):
            # Расшифровываем значение
            decrypted = decrypt_data(value)
            if decrypted is None:
                logger.warning(f"Не удалось расшифровать значение для ключа {key}")
            return decrypted
        else:
            return value
    
    async def get_json(self, key: str) -> Optional[dict]:
        """
        Получает JSON значение с автоматической расшифровкой
        
        Args:
            key: Ключ Redis
        
        Returns:
            Расшифрованный dict или None
        """
        value = await self.redis_client.get(key)
        
        if value is None:
            return None
        
        if self._should_encrypt(key):
            # Расшифровываем JSON
            return decrypt_json(value)
        else:
            try:
                return json.loads(value)
            except:
                return None
    
    # Прокси методы для остальных операций Redis
    async def delete(self, *keys):
        return await self.redis_client.delete(*keys)
    
    async def exists(self, key):
        return await self.redis_client.exists(key)
    
    async def expire(self, key, seconds):
        return await self.redis_client.expire(key, seconds)
    
    async def ttl(self, key):
        return await self.redis_client.ttl(key)
    
    async def keys(self, pattern):
        return await self.redis_client.keys(pattern)
    
    async def incr(self, key):
        return await self.redis_client.incr(key)
    
    async def setnx(self, key, value):
        return await self.redis_client.setnx(key, value)
    
    async def rpush(self, key, *values):
        return await self.redis_client.rpush(key, *values)
    
    async def lrange(self, key, start, end):
        return await self.redis_client.lrange(key, start, end)
    
    async def llen(self, key):
        return await self.redis_client.llen(key)
    
    async def ping(self):
        return await self.redis_client.ping()


def wrap_redis_client(redis_client):
    """
    Оборачивает Redis клиент для автоматического шифрования
    
    Args:
        redis_client: Оригинальный Redis клиент
    
    Returns:
        EncryptedRedisClient
    """
    return EncryptedRedisClient(redis_client)
