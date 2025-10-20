import os
import secrets
import logging
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from app.db import get_db
import app.db as database
from app.models import User


logger = logging.getLogger(__name__)

# Конфигурация JWT
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'RS256')
JWT_ISSUER = os.getenv('JWT_ISSUER', 'pixeltoo.ru')
JWT_AUDIENCE = os.getenv('JWT_AUDIENCE', 'mvp_clients')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '120'))

# Пути к ключам
PRIVATE_KEY_PATH = os.getenv('JWT_PRIVATE_KEY_PATH', '/var/mvp/jwt_private.pem')
PUBLIC_KEY_PATH = os.getenv('JWT_PUBLIC_KEY_PATH', '/var/mvp/jwt_public.pem')


def _load_or_create_keys():
    try:
        with open(PRIVATE_KEY_PATH, 'rb') as f:
            pem_private = f.read()
        private_key = serialization.load_pem_private_key(pem_private, password=None, backend=default_backend())
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            pem_public = f.read()
        public_key = serialization.load_pem_public_key(pem_public, backend=default_backend())
        logger.info("JWT ключи успешно загружены из файлов (auth)")
        return pem_private, pem_public
    except FileNotFoundError:
        logger.warning("JWT ключи не найдены, генерируем новые и сохраняем (auth)")
        from cryptography.hazmat.primitives.asymmetric import rsa
        private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key_obj = private_key_obj.public_key()
        pem_private = private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pem_public = public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        os.makedirs(os.path.dirname(PRIVATE_KEY_PATH), exist_ok=True)
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(pem_private)
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(pem_public)
        return pem_private, pem_public


_pem_private, _pem_public = _load_or_create_keys()


async def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    jti = secrets.token_urlsafe(32)
    to_encode["jti"] = jti
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iss": JWT_ISSUER, "aud": JWT_AUDIENCE})
    encoded = jwt.encode(to_encode, _pem_private, algorithm=JWT_ALGORITHM)
    if len(encoded) > 4096:
        logger.error("Сгенерирован слишком длинный JWT-токен")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера: токен слишком длинный")
    return encoded


async def verify_token(token: str):
    if len(token) > 4096:
        logger.warning("Получен слишком длинный JWT-токен")
        raise HTTPException(status_code=401, detail="Недопустимый токен: слишком длинный")
    try:
        payload = jwt.decode(token, _pem_public, algorithms=[JWT_ALGORITHM], audience=JWT_AUDIENCE)
        jti = payload.get("jti")
        if jti and database.redis_client and await database.redis_client.exists(f"jwt_blacklist:{jti}"):
            logger.warning("Токен отозван")
            raise HTTPException(status_code=401, detail="Токен отозван. Пожалуйста, войдите заново.")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токен истек. Пожалуйста, войдите заново.")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail="Недопустимый токен. Пожалуйста, войдите заново.")


security = HTTPBearer()


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: AsyncSession = Depends(get_db)) -> User:
    payload = await verify_token(credentials.credentials)
    sub = payload.get("sub")
    if not sub or len(sub) != 8 or not sub.isdigit():
        raise HTTPException(status_code=401, detail="Недопустимый токен: неверный идентификатор пользователя")
    async with db.begin():
        stmt = select(User).filter(User.unique_id == int(sub))
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="Пользователь не найден. Токен недействителен.")
        return user


def get_public_key_pem() -> str:
    return _pem_public.decode()


