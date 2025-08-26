import os
import ssl
import logging
import json
import random
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional
import bcrypt
import jwt
import secrets
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy.sql import text
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import redis.asyncio as redis
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from pydantic import BaseModel, field_validator
import re
import uvicorn
import websockets
import base64
import hashlib
from urllib.parse import parse_qs

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
    handlers=[
        logging.FileHandler("/var/mvp/mvp_server.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.propagate = False
logging.getLogger('apscheduler').setLevel(logging.WARNING)
logging.getLogger('uvicorn').setLevel(logging.WARNING)
logging.getLogger('websockets').setLevel(logging.WARNING)

# Конфигурация
SECRET_KEY = secrets.token_urlsafe(32)
ENCRYPTION_KEY_STR = 'YOU 32 BIT KEY'
ENCRYPTION_KEY = base64.urlsafe_b64decode(ENCRYPTION_KEY_STR)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
DB_URL = 'mysql+aiomysql://user:pass@localhost:3306/mlo_v'
REDIS_URL = 'redis://localhost:6379/0'
HTTP_PORT = 8088
WS_PORT = 8089
SSL_KEYFILE = 'privkey.pem'
SSL_CERTFILE = '/fullchain.pem'
RATE_LIMIT_CALLS = 20
RATE_LIMIT_PERIOD = 120
BLOCK_PERIOD = 60
OTP_LENGTH = 6
CSRF_SECRET = secrets.token_urlsafe(32)
DEBUG_MODE = os.getenv('DEBUG_MODE', '0') == '1'

# Проверка ключа шифрования
if len(ENCRYPTION_KEY) != 32:
    raise ValueError("Неверный размер ключа шифрования! Должен быть 32 байта.")
logger.info(f"Используемый ключ шифрования: {ENCRYPTION_KEY_STR}")

# Проверка наличия сертификатов
if not os.path.exists(SSL_KEYFILE) or not os.path.exists(SSL_CERTFILE):
    logger.error(f"Сертификаты SSL не найдены: key={SSL_KEYFILE}, cert={SSL_CERTFILE}")
    raise FileNotFoundError("Сертификаты SSL не найдены. Проверьте пути к файлам.")

# ICE-серверы
ICE_SERVERS = [
    {"urls": "stun:stun.l.google.com:19302"},
    {"urls": "stun:stun1.l.google.com:19302"},
    {"urls": "stun:stun2.l.google.com:19302"},
    {"urls": "turn:openrelay.metered.ca:80", "username": "openrelay.project", "credential": "openrelay"},
    {"urls": "turn:openrelay.metered.ca:443", "username": "openrelay.project", "credential": "openrelay"}
]

# FastAPI приложение
app = FastAPI(title="MVP - Melo Voice Project by Pixeltoo Lab", version="1.4")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://pixeltoo.ru"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)

# MySQL и Redis
engine = create_async_engine(DB_URL, pool_size=5, max_overflow=10, pool_timeout=30)
Base = declarative_base()
AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, autocommit=False, autoflush=False, expire_on_commit=False)
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    unique_id = Column(String(8), unique=True, index=True)
    hashed_phone = Column(String(64), unique=True, index=True, nullable=True)
    encrypted_phone = Column(Text)
    encrypted_name = Column(Text)
    encrypted_nickname = Column(Text)
    hashed_password = Column(String(255))
    last_activity = Column(DateTime, default=datetime.utcnow)
    subscriptions = Column(Text, default='[]')
    e2e_key = Column(Text)

async def init_db():
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'hashed_phone'"))
            if not result.fetchone():
                logger.info("Добавление столбца hashed_phone в таблицу users")
                await conn.execute(text("ALTER TABLE users ADD COLUMN hashed_phone VARCHAR(64) UNIQUE"))
            await conn.run_sync(Base.metadata.create_all)
            stmt = select(User).filter(User.hashed_phone.is_(None))
            result = await conn.execute(stmt)
            users = result.scalars().all()
            for user in users:
                if user.encrypted_phone:
                    try:
                        phone = decrypt_data(user.encrypted_phone)
                        user.hashed_phone = hashlib.sha256(phone.encode()).hexdigest()
                    except Exception as e:
                        logger.warning(f"Ошибка расшифровки телефона для пользователя {user.unique_id}: {str(e)}")
            stmt = select(User).filter((User.e2e_key.is_(None)) | (User.e2e_key == ''))
            result = await conn.execute(stmt)
            users_without_e2e = result.scalars().all()
            for user in users_without_e2e:
                e2e_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
                try:
                    user.e2e_key = encrypt_data(e2e_key)
                    logger.info(f"Создан e2e_key для пользователя {user.unique_id}")
                except Exception as e:
                    logger.error(f"Ошибка создания e2e_key для пользователя {user.unique_id}: {str(e)}")
            await conn.commit()
            logger.info(f"Обновлено {len(users)} записей с hashed_phone и {len(users_without_e2e)} с e2e_key")
        logger.info("Таблицы успешно созданы или уже существуют.")
        return True
    except Exception as e:
        logger.error(f"Ошибка создания таблиц или миграции: {str(e)}")
        return False

async def reconnect_db():
    if not await init_db():
        logger.error("Переподключение к БД не удалось.")

async def setup_db_and_scheduler():
    await init_db()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(reconnect_db, IntervalTrigger(minutes=5))
    scheduler.add_job(clean_redis, IntervalTrigger(hours=1))
    scheduler.start()
    logger.info("Планировщик запущен.")

async def clean_redis():
    try:
        patterns = ["otp:*", "pending_sub:*", "secret_sub:*", "rate_limit:*", "block:*", "ws_message:*"]
        for pattern in patterns:
            keys = await redis_client.keys(pattern)
            for key in keys:
                ttl = await redis_client.ttl(key)
                if ttl < 0:
                    await redis_client.delete(key)
        logger.debug(f"Очищены устаревшие ключи Redis: {patterns}")
    except Exception as e:
        logger.error(f"Ошибка очистки Redis: {str(e)}")

async def get_db() -> AsyncSession:
    session = AsyncSessionLocal()
    try:
        yield session
    except HTTPException:
        raise
    except Exception as e:
        await session.rollback()
        logger.error(f"Ошибка базы данных: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка базы данных: {str(e)}")
    finally:
        await session.close()

class RegisterRequest(BaseModel):
    phone: str
    name: str
    nickname: str
    password: str

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v):
        v = v.strip()
        if v.startswith('8'):
            v = '+7' + v[1:]
        if not re.match(r'^\+?[1-9]\d{1,14}$', v):
            raise ValueError('Недопустимый номер телефона. Должен быть в формате E.164 (например, +79123456789).')
        return v

    @field_validator('name', 'nickname')
    @classmethod
    def validate_names(cls, v):
        if len(v) < 1 or len(v) > 50 or not re.match(r'^[\w\s-]*$', v):
            raise ValueError('Недопустимое имя или никнейм. Длина от 1 до 50 символов, только буквы, цифры, пробелы, тире и подчеркивания.')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Пароль должен быть от 8 до 128 символов.')
        return v

class LoginRequest(BaseModel):
    identifier: str
    password: str
    otp: Optional[str] = None

class SubscribeRequest(BaseModel):
    target_id: str
    secret: bool = False
    csrf_token: str

    @field_validator('csrf_token')
    @classmethod
    def validate_csrf(cls, v):
        if v != CSRF_SECRET:
            raise ValueError('Неверный CSRF-токен.')
        return v

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded = jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)
    if len(encoded) > 4096:
        logger.error("Сгенерирован слишком длинный JWT-токен")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера: токен слишком длинный")
    return encoded

def verify_token(token: str):
    if len(token) > 4096:
        logger.warning("Получен слишком длинный JWT-токен")
        raise HTTPException(status_code=401, detail="Недопустимый токен: слишком длинный")
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.warning("Токен истек")
        raise HTTPException(status_code=401, detail="Токен истек. Пожалуйста, войдите заново.")
    except jwt.InvalidTokenError as e:
        logger.warning(f"Недопустимый токен: {str(e)}")
        raise HTTPException(status_code=401, detail="Недопустимый токен. Пожалуйста, войдите заново.")

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: AsyncSession = Depends(get_db)):
    payload = verify_token(credentials.credentials)
    if not payload.get("sub") or len(payload.get("sub")) != 8 or not payload.get("sub").isdigit():
        logger.warning("Неверный формат sub в JWT")
        raise HTTPException(status_code=401, detail="Недопустимый токен: неверный идентификатор пользователя")
    stmt = select(User).filter(User.unique_id == payload.get("sub"))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        logger.warning(f"Пользователь {payload.get('sub')} не найден")
        raise HTTPException(status_code=401, detail="Пользователь не найден. Токен недействителен.")
    user.last_activity = datetime.utcnow()
    await db.commit()
    return user

async def check_rate_limit(request: Request):
    client_ip = request.client.host
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', client_ip):
        logger.warning(f"Неверный формат IP: {client_ip}")
        raise HTTPException(status_code=400, detail="Неверный IP-адрес")
    rate_key = f"rate_limit:{client_ip}"
    block_key = f"block:{client_ip}"
    if await redis_client.exists(block_key):
        ttl = await redis_client.ttl(block_key)
        logger.warning(f"IP {client_ip} заблокирован, осталось {ttl} секунд")
        raise HTTPException(status_code=429, detail=f"IP {client_ip} заблокирован на {ttl/60:.1f} минут.")
    count = await redis_client.incr(rate_key)
    if count == 1:
        await redis_client.expire(rate_key, RATE_LIMIT_PERIOD)
    if count > RATE_LIMIT_CALLS:
        await redis_client.set(block_key, 1, ex=BLOCK_PERIOD)
        await redis_client.delete(rate_key)
        logger.warning(f"IP {client_ip} превысил лимит запросов: {count}")
        raise HTTPException(status_code=429, detail=f"Лимит запросов превышен ({RATE_LIMIT_CALLS} за {RATE_LIMIT_PERIOD} секунд).")

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    logger.debug(f"Проверка лимита для IP {request.client.host} на {request.url.path}")
    await check_rate_limit(request)
    response = await call_next(request)
    return response

def e2e_encrypt(data: dict, key: str):
    try:
        key_bytes = base64.urlsafe_b64decode(key)
        if len(key_bytes) != 32:
            logger.error("Неверный размер E2E ключа")
            raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера: неверный ключ шифрования")
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        plaintext = json.dumps(data).encode()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        result = base64.urlsafe_b64encode(nonce + ciphertext + encryptor.tag).decode()
        return result
    except Exception as e:
        logger.error(f"Ошибка E2E шифрования: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка E2E шифрования: {str(e)}")

def e2e_decrypt(encrypted: str, key: str):
    try:
        key_bytes = base64.urlsafe_b64decode(key)
        if len(key_bytes) != 32:
            logger.error("Неверный размер E2E ключа")
            raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера: неверный ключ шифрования")
        encrypted_bytes = base64.urlsafe_b64decode(encrypted)
        nonce = encrypted_bytes[:12]
        tag = encrypted_bytes[-16:]
        ciphertext = encrypted_bytes[12:-16]
        cipher = Cipher(algorithms.AES(key_bytes), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(plaintext.decode())
    except Exception as e:
        logger.error(f"Ошибка E2E расшифровки: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка E2E расшифровки: {str(e)}")

def encrypt_data(data: str) -> str:
    try:
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return base64.urlsafe_b64encode(nonce + ciphertext + encryptor.tag).decode()
    except Exception as e:
        logger.error(f"Ошибка шифрования данных: {str(e)}")
        return None

def decrypt_data(enc_data: str) -> str:
    try:
        encrypted_bytes = base64.urlsafe_b64decode(enc_data)
        nonce = encrypted_bytes[:12]
        tag = encrypted_bytes[-16:]
        ciphertext = encrypted_bytes[12:-16]
        cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except Exception as e:
        logger.error(f"Ошибка расшифровки данных: {str(e)}")
        return None

def generate_otp():
    return ''.join(secrets.choice('0123456789') for _ in range(OTP_LENGTH))

@app.post("/generate_otp")
async def generate_otp_endpoint(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        identifier = req.identifier.strip()
        if identifier.startswith('8'):
            identifier = '+7' + identifier[1:]
        user = None
        if re.match(r'^\d{8}$', identifier):
            stmt = select(User).filter(User.unique_id == identifier)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
        else:
            hash_identifier = hashlib.sha256(identifier.encode()).hexdigest()
            stmt = select(User).filter(User.hashed_phone == hash_identifier)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
        if not user:
            logger.info(f"Пользователь с идентификатором {identifier} не найден")
            raise HTTPException(404, detail="Пользователь не найден.")
        if not bcrypt.checkpw(req.password.encode(), user.hashed_password.encode()):
            logger.warning(f"Неверный пароль для {identifier}")
            raise HTTPException(status_code=401, detail="Неверный пароль.")
        otp = generate_otp()
        await redis_client.set(f"otp:{user.unique_id}", otp, ex=300)
        logger.info(f"OTP сгенерирован для {user.unique_id}: {otp}")
        return {"status": "OTP сгенерирован", "otp": otp if DEBUG_MODE else None}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка генерации OTP: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка генерации OTP: {str(e)}")

async def generate_unique_id(db: AsyncSession) -> str:
    for _ in range(10):
        uid = str(random.randint(10000000, 99999999))
        stmt = select(User).filter(User.unique_id == uid)
        result = await db.execute(stmt)
        if not result.scalar_one_or_none():
            return uid
    logger.error("Не удалось сгенерировать уникальный ID")
    raise HTTPException(status_code=500, detail="Ошибка генерации уникального ID.")

@app.post("/register")
async def register(req: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        hashed_phone = hashlib.sha256(req.phone.encode()).hexdigest()
        stmt = select(User).filter(User.hashed_phone == hashed_phone)
        result = await db.execute(stmt)
        if result.scalar_one_or_none():
            logger.warning(f"Телефон {req.phone} уже зарегистрирован")
            raise HTTPException(status_code=400, detail="Телефон уже зарегистрирован.")
        hashed_pw = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
        e2e_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        enc_e2e_key = encrypt_data(e2e_key)
        if enc_e2e_key is None:
            logger.error("Не удалось зашифровать e2e_key")
            raise HTTPException(status_code=500, detail="Ошибка создания ключа шифрования")
        user = User(
            unique_id=await generate_unique_id(db),
            hashed_phone=hashed_phone,
            encrypted_phone=encrypt_data(req.phone),
            encrypted_name=encrypt_data(req.name),
            encrypted_nickname=encrypt_data(req.nickname),
            hashed_password=hashed_pw,
            e2e_key=enc_e2e_key
        )
        db.add(user)
        await db.commit()
        logger.info(f"Пользователь зарегистрирован: {user.unique_id}")
        return {"unique_id": user.unique_id, "e2e_key": e2e_key}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка регистрации: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка регистрации: {str(e)}")

@app.post("/login")
async def login(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    try:
        identifier = req.identifier.strip()
        if identifier.startswith('8'):
            identifier = '+7' + identifier[1:]
        user = None
        if re.match(r'^\d{8}$', identifier):
            stmt = select(User).filter(User.unique_id == identifier)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
        else:
            hash_identifier = hashlib.sha256(identifier.encode()).hexdigest()
            stmt = select(User).filter(User.hashed_phone == hash_identifier)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
        if not user:
            logger.info(f"Пользователь с идентификатором {identifier} не найден")
            raise HTTPException(status_code=401, detail="Пользователь не найден.")
        if not bcrypt.checkpw(req.password.encode(), user.hashed_password.encode()):
            logger.warning(f"Неверный пароль для {identifier}")
            raise HTTPException(status_code=401, detail="Неверный пароль.")
        if req.otp:
            stored_otp = await redis_client.get(f"otp:{user.unique_id}")
            if stored_otp != req.otp:
                logger.warning(f"Неверный OTP для {user.unique_id}")
                raise HTTPException(status_code=401, detail="Неверный OTP.")
            await redis_client.delete(f"otp:{user.unique_id}")
        e2e_key = decrypt_data(user.e2e_key) if user.e2e_key else None
        if e2e_key is None:
            e2e_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
            enc_e2e_key = encrypt_data(e2e_key)
            if enc_e2e_key is None:
                logger.error(f"Не удалось зашифровать новый e2e_key для {user.unique_id}")
                raise HTTPException(status_code=500, detail="Ошибка создания ключа шифрования")
            user.e2e_key = enc_e2e_key
            await db.commit()
        token = create_access_token({"sub": user.unique_id})
        user.last_activity = datetime.utcnow()
        await db.commit()
        logger.info(f"Пользователь вошел: {user.unique_id}")
        return {"access_token": token, "token_type": "bearer", "csrf_token": CSRF_SECRET, "e2e_key": e2e_key}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка входа: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка входа: {str(e)}")

@app.get("/ice_servers")
async def get_ice_servers(current_user: User = Depends(get_current_user)):
    logger.debug(f"Запрос ICE-серверов от {current_user.unique_id}")
    return {"ice_servers": ICE_SERVERS}

@app.post("/subscribe")
async def subscribe(req: SubscribeRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    try:
        stmt = select(User).filter(User.unique_id == req.target_id)
        result = await db.execute(stmt)
        target = result.scalar_one_or_none()
        if not target:
            logger.warning(f"Целевой пользователь {req.target_id} не найден")
            raise HTTPException(404, detail="Целевой пользователь не найден.")
        if req.target_id == current_user.unique_id:
            logger.warning("Попытка подписки на себя")
            raise HTTPException(400, detail="Нельзя подписаться на себя.")
        subs = json.loads(current_user.subscriptions)
        if req.target_id in subs:
            logger.warning(f"Уже подписан на {req.target_id}")
            raise HTTPException(400, detail="Уже подписаны на этого пользователя.")
        pending_key = f"pending_sub:{req.target_id}"
        await redis_client.sadd(pending_key, current_user.unique_id)
        await redis_client.expire(pending_key, 86400)
        if req.secret:
            await redis_client.set(f"secret_sub:{current_user.unique_id}:{req.target_id}", 1, ex=3600)
        target_e2e_key = decrypt_data(target.e2e_key)
        if target_e2e_key is None:
            logger.error(f"Не удалось расшифровать e2e_key для {req.target_id}")
            raise HTTPException(status_code=500, detail="Ошибка шифрования сообщения")
        notification = {
            "type": "subscription_request",
            "from_id": current_user.unique_id,
            "from_phone": decrypt_data(current_user.encrypted_phone),
            "secret": req.secret
        }
        encrypted_notification = e2e_encrypt(notification, target_e2e_key)
        message_key = f"ws_message:{req.target_id}"
        await redis_client.rpush(message_key, encrypted_notification)
        await redis_client.expire(message_key, 86400)
        if target.unique_id in active_connections:
            try:
                await active_connections[target.unique_id].send(encrypted_notification)
                logger.info(f"Отправлено сообщение от {current_user.unique_id} к {req.target_id}")
            except Exception as e:
                logger.warning(f"Не удалось отправить сообщение {req.target_id}: {str(e)}")
        else:
            logger.warning(f"Пользователь {req.target_id} не в сети")
        logger.info(f"Запрос на подписку: {current_user.unique_id} -> {req.target_id} (secret: {req.secret})")
        return {"status": "subscription_requested"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка подписки: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка подписки: {str(e)}")

@app.post("/confirm_subscribe")
async def confirm_subscribe(req: SubscribeRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    try:
        pending_key = f"pending_sub:{current_user.unique_id}"
        if not await redis_client.sismember(pending_key, req.target_id):
            logger.warning(f"Нет ожидающего запроса от {req.target_id}")
            raise HTTPException(400, detail="Нет ожидающего запроса на подписку.")
        subs_current = json.loads(current_user.subscriptions)
        subs_current.append(req.target_id)
        current_user.subscriptions = json.dumps(subs_current)
        stmt = select(User).filter(User.unique_id == req.target_id)
        result = await db.execute(stmt)
        target = result.scalar_one_or_none()
        if not target:
            logger.warning(f"Целевой пользователь {req.target_id} не найден")
            raise HTTPException(404, detail="Целевой пользователь не найден.")
        subs_target = json.loads(target.subscriptions)
        subs_target.append(current_user.unique_id)
        target.subscriptions = json.dumps(subs_target)
        await db.commit()
        await redis_client.srem(pending_key, req.target_id)
        target_e2e_key = decrypt_data(target.e2e_key)
        if target_e2e_key is None:
            logger.error(f"Не удалось расшифровать e2e_key для {req.target_id}")
            raise HTTPException(status_code=500, detail="Ошибка шифрования сообщения")
        notification = {
            "type": "subscription_confirmed",
            "from_id": current_user.unique_id,
            "from_phone": decrypt_data(current_user.encrypted_phone)
        }
        encrypted_notification = e2e_encrypt(notification, target_e2e_key)
        message_key = f"ws_message:{req.target_id}"
        await redis_client.rpush(message_key, encrypted_notification)
        await redis_client.expire(message_key, 86400)
        if target.unique_id in active_connections:
            try:
                await active_connections[target.unique_id].send(encrypted_notification)
                logger.info(f"Отправлено сообщение от {current_user.unique_id} к {req.target_id}")
            except Exception as e:
                logger.warning(f"Не удалось отправить сообщение {req.target_id}: {str(e)}")
        logger.info(f"Подписка подтверждена: {current_user.unique_id} <-> {req.target_id}")
        return {"status": "confirmed"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка подтверждения подписки: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка подтверждения подписки: {str(e)}")

@app.get("/contacts")
async def get_contacts(current_user: User = Depends(get_current_user)):
    try:
        cache_key = f"contacts:{current_user.unique_id}"
        cached = await redis_client.get(cache_key)
        if cached:
            return {"contacts": json.loads(cached)}
        subs = json.loads(current_user.subscriptions)
        await redis_client.set(cache_key, json.dumps(subs), ex=300)
        return {"contacts": subs}
    except Exception as e:
        logger.error(f"Ошибка получения контактов: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения контактов: {str(e)}")

@app.get("/debug/users")
async def debug_users(db: AsyncSession = Depends(get_db)):
    if not DEBUG_MODE:
        logger.warning("Попытка доступа к /debug/users при выключенном DEBUG_MODE")
        raise HTTPException(status_code=403, detail="Debug-режим отключен")
    try:
        stmt = select(User)
        result = await db.execute(stmt)
        users = result.scalars().all()
        user_data = [
            {
                "unique_id": u.unique_id,
                "hashed_phone": u.hashed_phone,
                "encrypted_phone": u.encrypted_phone,
                "decrypted_phone": decrypt_data(u.encrypted_phone) if u.encrypted_phone else None,
                "e2e_key": decrypt_data(u.e2e_key) if u.e2e_key else None
            } for u in users
        ]
        return {"users": user_data}
    except Exception as e:
        logger.error(f"Ошибка получения пользователей: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения пользователей: {str(e)}")

# WebSocket сервер
active_connections = {}

async def websocket_handler(websocket, path: str):
    logger.debug(f"WebSocket подключение: path={path}")
    try:
        query = parse_qs(path.split("?", 1)[1] if "?" in path else "")
        token = query.get("token", [None])[0]
        if not token:
            await websocket.close(code=1008, reason="Отсутствует токен авторизации")
            return
        payload = verify_token(token)
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=1008, reason="Токен не содержит идентификатор пользователя")
            return
        async with AsyncSessionLocal() as db:
            stmt = select(User).filter(User.unique_id == user_id)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
            if not user:
                await websocket.close(code=1008, reason="Пользователь не найден")
                return
            e2e_key = decrypt_data(user.e2e_key) if user.e2e_key else None
            if e2e_key is None:
                e2e_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
                enc_e2e_key = encrypt_data(e2e_key)
                if enc_e2e_key is None:
                    await websocket.close(code=1008, reason="Ошибка создания ключа шифрования")
                    return
                user.e2e_key = enc_e2e_key
                await db.commit()
        active_connections[user_id] = websocket
        logger.info(f"WS подключен: {user_id}")
        message_key = f"ws_message:{user_id}"
        messages = await redis_client.lrange(message_key, 0, -1)
        if messages:
            for msg in messages:
                try:
                    await websocket.send(msg)
                    logger.debug(f"Отправлено сохраненное сообщение для {user_id}")
                except Exception as e:
                    logger.error(f"Ошибка отправки сохраненного сообщения для {user_id}: {str(e)}")
            await redis_client.delete(message_key)
        try:
            while True:
                try:
                    data_enc = await websocket.recv()
                    if not isinstance(data_enc, str):
                        logger.warning(f"Получены нестроковые данные от {user_id}")
                        continue
                    data = e2e_decrypt(data_enc, e2e_key)
                    if not isinstance(data, dict) or 'type' not in data or 'target' not in data:
                        logger.warning(f"Неверный формат данных от {user_id}: {data}")
                        continue
                    target_id = data['target']
                    if not re.match(r'^\d{8}$', target_id):
                        logger.warning(f"Неверный target_id от {user_id}: {target_id}")
                        continue
                    async with AsyncSessionLocal() as db:
                        stmt = select(User).filter(User.unique_id == user_id)
                        result = await db.execute(stmt)
                        user = result.scalar_one_or_none()
                        if target_id not in json.loads(user.subscriptions):
                            logger.warning(f"{user_id} не подписан на {target_id}")
                            continue
                        stmt = select(User).filter(User.unique_id == target_id)
                        result = await db.execute(stmt)
                        target_user = result.scalar_one_or_none()
                        if not target_user:
                            logger.warning(f"Целевой пользователь {target_id} не найден")
                            continue
                        target_e2e_key = decrypt_data(target_user.e2e_key)
                        if target_e2e_key is None:
                            logger.error(f"Не удалось расшифровать e2e_key для {target_id}")
                            continue
                    encrypted_response = e2e_encrypt(data, target_e2e_key)
                    message_key = f"ws_message:{target_id}"
                    await redis_client.rpush(message_key, encrypted_response)
                    await redis_client.expire(message_key, 86400)
                    if target_id in active_connections:
                        try:
                            await active_connections[target_id].send(encrypted_response)
                            logger.debug(f"Отправлено сообщение от {user_id} к {target_id}")
                        except Exception as e:
                            logger.warning(f"Не удалось отправить сообщение {target_id}: {str(e)}")
                    else:
                        logger.warning(f"Пользователь {target_id} не в сети")
                except websockets.exceptions.ConnectionClosed:
                    logger.debug(f"WebSocket {user_id} закрыт")
                    break
                except ssl.SSLError as e:
                    logger.error(f"Ошибка SSL в WS для {user_id}: {str(e)}")
                    break
                except Exception as e:
                    logger.error(f"Ошибка обработки сообщения WS для {user_id}: {str(e)}")
                    continue
        finally:
            active_connections.pop(user_id, None)
            logger.info(f"WS отключен: {user_id}")
    except Exception as e:
        logger.error(f"Критическая ошибка авторизации WS: {str(e)}")
        await websocket.close(code=1008, reason=f"Ошибка сервера: {str(e)}")

async def delete_inactive():
    try:
        async with AsyncSessionLocal() as db:
            threshold = datetime.utcnow() - timedelta(days=365)
            stmt = select(User).filter(User.last_activity < threshold)
            result = await db.execute(stmt)
            inactive = result.scalars().all()
            for u in inactive:
                await redis_client.delete(f"pending_sub:{u.unique_id}")
                await redis_client.delete(f"ws_message:{u.unique_id}")
                await db.delete(u)
            await db.commit()
            logger.info(f"Удалено {len(inactive)} неактивных пользователей")
    except Exception as e:
        logger.error(f"Ошибка удаления неактивных пользователей: {str(e)}")

async def main():
    try:
        await setup_db_and_scheduler()
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        # Используем более широкий список шифров для совместимости
        ssl_context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256')
        ssl_context.load_cert_chain(certfile=SSL_CERTFILE, keyfile=SSL_KEYFILE)
        logger.info("SSL-сертификаты успешно загружены")
        
        ws_server = await websockets.serve(
            websocket_handler,
            "0.0.0.0",
            WS_PORT,
            ssl=ssl_context,
            max_size=2**20,
            ping_interval=30,
            ping_timeout=20
        )
        
        http_config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=HTTP_PORT,
            ssl_keyfile=SSL_KEYFILE,
            ssl_certfile=SSL_CERTFILE,
            ssl_version=ssl.PROTOCOL_TLS_SERVER
            # Убираем явное указание шифров для HTTP, используем значения по умолчанию
        )
        http_server = uvicorn.Server(http_config)
        await asyncio.gather(http_server.serve(), ws_server.wait_closed())
    except FileNotFoundError as e:
        logger.error(f"Ошибка загрузки сертификатов: {str(e)}")
        raise
    except ssl.SSLError as e:
        logger.error(f"Ошибка конфигурации SSL: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Критическая ошибка запуска сервера: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
