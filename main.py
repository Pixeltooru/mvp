# pyright: reportMissingImports=false
import os
import ssl
import logging
from logging.handlers import RotatingFileHandler
import json
import random
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Callable, Any
import bcrypt
import jwt
import secrets
from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from sqlalchemy import select, Column, Integer, String, DateTime, Text, ForeignKey, or_, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import text
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from app.push import send_webpush, get_vapid_keys
import app.db as database
from app.auth import create_access_token, verify_token, get_current_user, security
from app.routes.sessions import build_router as build_sessions_router
from app.routes.scheduler import build_router as build_scheduler_router
from app.routes.devices import build_router as build_devices_router
from app.routes.chats import build_router as build_chats_router
from app.routes.avatars import build_router as build_avatars_router
from app.routes.chat_messages import build_router as build_chat_messages_router
from app.routes.chat_members import build_router as build_chat_members_router
from app.routes.invites import build_router as build_invites_router
from app.routes.message_mgmt import build_router as build_message_mgmt_router
from app.routes.user_status import build_router as build_user_status_router
from pydantic import BaseModel, field_validator
import re
import uuid
import uvicorn
import websockets
import base64
import hashlib
from urllib.parse import parse_qs
from starlette.exceptions import HTTPException as StarletteHTTPException
import ipaddress
from starlette.middleware.base import BaseHTTPMiddleware
from tenacity import retry, stop_after_attempt, wait_fixed

from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Загружаем переменные из .env файла
load_dotenv(dotenv_path='.env')

# Настройка логирования с маскировкой sensitive data
log_file_path = os.getenv('LOG_FILE_PATH', "/var/mvp/mvp_server.log")
handler = RotatingFileHandler(log_file_path, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
    handlers=[
        handler,
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.propagate = False
logging.getLogger('apscheduler').setLevel(logging.WARNING)
logging.getLogger('uvicorn').setLevel(logging.WARNING)
logging.getLogger('websockets').setLevel(logging.INFO)
logging.getLogger('sqlalchemy.engine').setLevel(logging.DEBUG)

def mask_sensitive(data: str) -> str:
    """Маскировка sensitive data для логов (phone, identifiers, device_id)"""
    if not data:
        return 'None'
    return hashlib.sha256(data.encode()).hexdigest()[:8] + '***'

# Конфигурация
SERVER_VERSION = "3.1.1"
ENCRYPTION_KEY_STR = os.getenv('ENCRYPTION_KEY_STR')
if not ENCRYPTION_KEY_STR:
    logger.error("ENCRYPTION_KEY_STR не задан в env vars!")
    raise ValueError("ENCRYPTION_KEY_STR не задан в env vars!")
ENCRYPTION_KEY = base64.urlsafe_b64decode(ENCRYPTION_KEY_STR)
JWT_ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120
DB_URL = os.getenv('DB_URL')
if not DB_URL:
    logger.error("DB_URL не задан в env vars!")
    raise ValueError("DB_URL не задан в env vars!")
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD')
if not REDIS_PASSWORD:
    logger.warning("REDIS_PASSWORD не задан, рекомендуется установить для безопасности")
HTTP_PORT = 8088
WS_PORT = 8089
SSL_KEYFILE = '/etc/letsencrypt/live/pixeltoo.ru/privkey.pem'
SSL_CERTFILE = '/etc/letsencrypt/live/pixeltoo.ru/fullchain.pem'
RATE_LIMIT_CALLS = 20
RATE_LIMIT_PERIOD = 120
BLOCK_PERIOD = 60
WS_RATE_LIMIT_MESSAGES = 100
WS_RATE_LIMIT_PERIOD = 60
WS_MAX_CONNECTIONS_PER_IP = 5
DEBUG_MODE = os.getenv('DEBUG_MODE', '1') == '1'
FAILED_LOGIN_LIMIT = 5
FAILED_LOGIN_BLOCK_PERIOD = 300
HISTORY_TTL = 1209600
E2E_KEY_ROTATION_DAYS = 180
APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')
if not APP_SECRET_KEY or len(APP_SECRET_KEY) < 32:
    logger.error("APP_SECRET_KEY не задан или слишком короткий!")
    raise ValueError("APP_SECRET_KEY должен быть минимум 32 символа")
JWT_ISSUER = "pixeltoo.ru"
JWT_AUDIENCE = "mvp_clients"

last_cert_mtime = None
last_key_mtime = None
initialized = False

logger.info(f"Запуск сервера MVP - Melo Voice Project by Pixeltoo Lab, версия {SERVER_VERSION}")

PRIVATE_KEY_PATH = os.getenv('JWT_PRIVATE_KEY_PATH', '/var/mvp/jwt_private.pem')
PUBLIC_KEY_PATH = os.getenv('JWT_PUBLIC_KEY_PATH', '/var/mvp/jwt_public.pem')
try:
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        pem_private = f.read()
    private_key = serialization.load_pem_private_key(pem_private, password=None, backend=default_backend())
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        pem_public = f.read()
    public_key = serialization.load_pem_public_key(pem_public, backend=default_backend())
    logger.info("JWT ключи успешно загружены из файлов")
except FileNotFoundError:
    logger.warning("JWT ключи не найдены, генерируем новые и сохраняем")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(pem_private)
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(pem_public)
logger.debug("JWT ключи инициализированы")

if len(ENCRYPTION_KEY) != 32:
    logger.error("Неверный размер ключа шифрования! Должен быть 32 байта.")
    raise ValueError("Неверный размер ключа шифрования! Должен быть 32 байта.")
logger.info(f"Используемый ключ шифрования: {mask_sensitive(ENCRYPTION_KEY_STR)}")

if not os.path.exists(SSL_KEYFILE) or not os.path.exists(SSL_CERTFILE):
    logger.error(f"Сертификаты SSL не найдены: key={SSL_KEYFILE}, cert={SSL_CERTFILE}")
    raise FileNotFoundError("Сертификаты SSL не найдены. Проверьте пути к файлам.")

try:
    test_payload = {"sub": "test123", "exp": datetime.utcnow() + timedelta(minutes=1), "iss": JWT_ISSUER, "aud": JWT_AUDIENCE}
    test_token = jwt.encode(test_payload, pem_private, algorithm=JWT_ALGORITHM)
    decoded = jwt.decode(test_token, pem_public, algorithms=[JWT_ALGORITHM], audience=JWT_AUDIENCE)
    if decoded.get("sub") != "test123" or decoded.get("iss") != JWT_ISSUER:
        raise ValueError("Ошибка в генерации или декодировании JWT-токена")
    logger.info("Проверка JWT-токена прошла успешно")
except Exception as e:
    logger.error(f"Ошибка проверки JWT: {str(e)}")
    raise ValueError(f"Ошибка в настройке JWT: {str(e)}")

ICE_SERVERS = [
    {"urls": "stun:stun.l.google.com:19302"},
    {"urls": "stun:stun1.l.google.com:19302"},
    {"urls": "stun:stun2.l.google.com:19302"},
    {"urls": "turn:openrelay.metered.ca:80", "username": "openrelayproject", "credential": "openrelay"},
    {"urls": "turn:openrelay.metered.ca:443", "username": "openrelayproject", "credential": "openrelay"},
    {"urls": "stun:stun3.l.google.com:19302"},
    {"urls": "stun:stun4.l.google.com:19302"},
    {"urls": "stun:stun.sipgate.net:3478"},
    {"urls": "stun:stun.stunprotocol.org:3478"},
    {"urls": "stun:stun.voipbuster.com:3478"},
    {"urls": "stun:stun1.voiceeclipse.net:3478"},
    {"urls": "stun:stun.ekiga.net:3478"},
    {"urls": "stun:stun.ideasip.com:3478"},
    {"urls": "stun:stun.voiparound.com:3478"},
    {"urls": "stun:stun.rixtelecom.se:3478"},
    {"urls": "stun:stun.counterpath.com:3478"}
]

app = FastAPI(title="MVP - Melo Voice Project by Pixeltoo Lab", version=SERVER_VERSION)

# Единый формат ошибок API
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={
        "ok": False,
        "error": {
            "code": exc.status_code,
            "message": exc.detail,
            "path": str(request.url.path),
        }
    })

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {str(exc)}")
    return JSONResponse(status_code=500, content={
        "ok": False,
        "error": {
            "code": 500,
            "message": "Внутренняя ошибка сервера",
            "path": str(request.url.path),
        }
    })
# Роутеры подключаются после инициализации зависимостей в setup_db_and_scheduler

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Запрещаем отдачу исходников фронта напрямую
        raw_path = request.url.path or ''
        if raw_path.startswith('/src/') or raw_path.startswith('/node_modules') or raw_path.endswith(('.jsx', '.tsx', '.ts', '.map')):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        response = await call_next(request)
        response.headers['Content-Security-Policy'] = (
            "default-src 'self' file:; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' https://pixeltoo.ru:8088 https://mlo.pixeltoo.ru https://mlo.pixeltoo.ru:8088 wss://pixeltoo.ru:8089 wss://mlo.pixeltoo.ru:8089;"
        )
        response.headers['Strict-Transport-Security'] = "max-age=31536000; includeSubDomains; preload"
        response.headers['X-Frame-Options'] = "DENY"
        response.headers['X-Content-Type-Options'] = "nosniff"
        response.headers['Referrer-Policy'] = "strict-origin-when-cross-origin"
        return response

async def process_offline_push_queue():
    try:
        # Проходим по активным оффлайн сообщениям и отправляем пуш
        # Формат ключей ws_message:<uid>; пуши шлем только если пользователь оффлайн
        keys = await database.redis_client.keys("ws_message:*")
        for message_key in keys:
            uid = message_key.split(":", 1)[1]
            if uid in active_connections:
                continue  # онлайн — доставит WS
            push_rec_raw = await database.redis_client.get(f"push:{uid}")
            if not push_rec_raw:
                continue
            try:
                push_rec = json.loads(push_rec_raw)
            except Exception:
                continue
            platform = (push_rec.get("platform") or "web").lower()
            messages = await database.redis_client.lrange(message_key, 0, 0)
            if not messages:
                continue
            preview = "Новое сообщение"
            try:
                first = json.loads(messages[0])
                # best-effort preview for relay envelope
                preview = first.get("type") or preview
            except Exception:
                pass
            if platform == 'web' and push_rec.get("subscription"):
                try:
                    send_webpush(push_rec["subscription"], {
                        "title": "MVP",
                        "body": preview,
                        "tag": "chat",
                    })
                except HTTPException as e:
                    if e.status_code in (404, 410):
                        await database.redis_client.delete(f"push:{uid}")
            # Для мобильных платформ: интеграция с FCM/APNs может быть добавлена здесь
    except Exception as e:
        logger.debug(f"process_offline_push_queue error: {str(e)}")

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://mlo.pixeltoo.ru", "https://pixeltoo.ru", "file://"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS", "PUT"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
)

# DB и Redis инициализируются в app/db.py

from app.models import Base, User, E2EKey, Subscription, SecretE2EKey, Chat, ChatMember, UserSession, UserStatus, MessageReadStatus

class Plugin:
    def __init__(self, name: str):
        self.name = name
        self.hooks: Dict[str, List[Callable]] = {
            'pre_register': [],
            'post_register': [],
            'pre_login': [],
            'post_login': [],
            'pre_subscribe': [],
            'post_subscribe': [],
        }

    def register_hook(self, hook_name: str, callback: Callable):
        if hook_name in self.hooks:
            self.hooks[hook_name].append(callback)
            logger.debug(f"Плагин {self.name}: зарегистрирован хук {hook_name}")
        else:
            logger.warning(f"Плагин {self.name}: неизвестный хук {hook_name}")

    async def execute_hook(self, hook_name: str, *args, **kwargs) -> Any:
        results = []
        for callback in self.hooks.get(hook_name, []):
            try:
                result = await callback(*args, **kwargs) if asyncio.iscoroutinefunction(callback) else callback(*args, **kwargs)
                results.append(result)
                logger.debug(f"Плагин {self.name}: выполнен хук {hook_name}, результат: {result}")
            except Exception as e:
                logger.error(f"Плагин {self.name}: ошибка в хуке {hook_name}: {str(e)}")
        return results

plugins: List[Plugin] = []

def register_plugin(name: str) -> Plugin:
    plugin = Plugin(name)
    plugins.append(plugin)
    logger.info(f"Зарегистрирован плагин: {name}")
    return plugin

activity_plugin = register_plugin("ActivityLogger")
activity_plugin.register_hook('post_register', lambda user: logger.info(f"ActivityPlugin: Зарегистрирован пользователь {user.unique_id}"))
activity_plugin.register_hook('post_login', lambda user: logger.info(f"ActivityPlugin: Пользователь {user.unique_id} вошел в систему"))

audit_plugin = register_plugin("AuditLogger")
audit_plugin.register_hook('post_register', lambda user: logger.info(f"Audit: Registration for {user.unique_id}"))
audit_plugin.register_hook('post_login', lambda user: logger.info(f"Audit: Login for {user.unique_id}"))
audit_plugin.register_hook('post_subscribe', lambda req, user, target: logger.info(f"Audit: Subscription {user.unique_id} -> {target.unique_id}"))

async def ensure_innodb(conn, table_name):
    try:
        result = await conn.execute(text(f"SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '{table_name}'"))
        row = result.fetchone()
        if row and row[0] != 'InnoDB':
            await conn.execute(text(f"ALTER TABLE `{table_name}` ENGINE=InnoDB"))
            logger.info(f"Altered {table_name} to InnoDB")
    except Exception as e:
        logger.warning(f"Could not alter {table_name} to InnoDB: {e}")

async def init_db():
    try:
        async with database.engine.begin() as conn:
            # Ensure users is InnoDB first
            result = await conn.execute(text("SHOW TABLES LIKE 'users'"))
            if result.fetchone():
                await ensure_innodb(conn, 'users')
                logger.info("Ensured users table is InnoDB")
            
            tables_to_create = ['users', 'e2e_keys', 'subscriptions', 'secret_e2e_keys', 'chats', 'chat_members']
            for table in tables_to_create:
                result = await conn.execute(text(f"SHOW TABLES LIKE '{table}'"))
                table_exists = result.fetchone() is not None
                if not table_exists:
                    logger.info(f"Таблица {table} не существует, создаем...")
                    await conn.run_sync(Base.metadata.create_all)
                    logger.info(f"Таблица {table} создана")
                else:
                    logger.info(f"Таблица {table} существует, проверяем столбцы...")
                    await ensure_innodb(conn, table)
            
            # Миграция для users (удаление subscriptions, добавление если нужно)
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'subscriptions'"))
            if result.fetchone():
                logger.info("Миграция subscriptions в новую таблицу...")
                async with database.AsyncSessionLocal() as session:
                    async with session.begin():
                        stmt = text("SELECT id, subscriptions FROM users WHERE subscriptions != '[]'")
                        result = await session.execute(stmt)
                        rows = result.fetchall()
                        for row in rows:
                            user_id = row[0]
                            try:
                                subs = json.loads(row[1])
                                stmt_user = select(User).filter(User.id == user_id)
                                result_user = await session.execute(stmt_user)
                                user = result_user.scalar_one_or_none()
                                if not user:
                                    continue
                                for target_str in subs:
                                    target_unique = int(target_str.strip('"\''))
                                    stmt_target = select(User.id).filter(User.unique_id == target_unique)
                                    result_target = await session.execute(stmt_target)
                                    target_pk = result_target.scalar_one_or_none()
                                    if target_pk:
                                        sub = Subscription(user_id=user.id, target_id=target_pk, status='accepted')
                                        session.add(sub)
                                logger.debug(f"Мигрированы подписки для user_id={user_id}")
                            except Exception as e:
                                logger.warning(f"Ошибка миграции для user_id={user_id}: {str(e)}")
                        await session.commit()
                # Удаляем столбец subscriptions
                await conn.execute(text("ALTER TABLE users DROP COLUMN subscriptions"))
                logger.info("Миграция subscriptions завершена, столбец удален")
            
            # Миграция для e2e_keys из users.public_e2e_key
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'public_e2e_key'"))
            if result.fetchone():
                logger.info("Миграция public_e2e_key в e2e_keys...")
                async with database.AsyncSessionLocal() as session:
                    async with session.begin():
                        stmt = text("SELECT id, public_e2e_key FROM users WHERE public_e2e_key IS NOT NULL")
                        result = await session.execute(stmt)
                        rows = result.fetchall()
                        for row in rows:
                            user_id = row[0]
                            public_e2e_key = row[1]
                            if public_e2e_key:
                                try:
                                    enc_key = encrypt_data(public_e2e_key)
                                    # пропускаем, если запись уже существует
                                    existing_stmt = select(E2EKey).filter(E2EKey.user_id == user_id)
                                    existing_res = await session.execute(existing_stmt)
                                    existing = existing_res.scalar_one_or_none()
                                    if existing:
                                        logger.debug(f"Пропущен e2e_key: уже существует для user_id={user_id}")
                                    else:
                                        e2e = E2EKey(user_id=user_id, encrypted_public_key=enc_key, updated_at=datetime.utcnow())
                                        session.add(e2e)
                                        logger.debug(f"Мигрирован e2e_key для user_id={user_id}")
                                except Exception as e:
                                    logger.warning(f"Ошибка миграции e2e_key для user_id={user_id}: {str(e)}")
                        await session.commit()
                # Удаляем столбец public_e2e_key
                await conn.execute(text("ALTER TABLE users DROP COLUMN public_e2e_key"))
                logger.info("Миграция e2e_keys завершена, столбец удален")
            
            # Проверяем/добавляем id column
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'id'"))
            if not result.fetchone():
                # Check if unique_id is current PK
                pk_result = await conn.execute(text("SHOW KEYS FROM users WHERE Key_name = 'PRIMARY'"))
                pk_rows = pk_result.fetchall()
                if any('unique_id' in str(row) for row in pk_rows):
                    await conn.execute(text("ALTER TABLE users DROP PRIMARY KEY"))
                    logger.info("Dropped old PRIMARY KEY on unique_id")
                await conn.execute(text("ALTER TABLE users ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY FIRST"))
                logger.info("Added id column as PRIMARY KEY")
            
            # Проверяем/добавляем unique_id column
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'unique_id'"))
            if not result.fetchone():
                await conn.execute(text("ALTER TABLE users ADD COLUMN unique_id INT UNIQUE KEY AFTER id"))
                logger.info("Added unique_id column")
            
            # Проверяем/добавляем другие столбцы для users
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'hashed_phone'"))
            if not result.fetchone():
                try:
                    await conn.execute(text("ALTER TABLE users ADD COLUMN hashed_phone VARCHAR(64) UNIQUE AFTER encrypted_phone"))
                    logger.info("Столбец hashed_phone добавлен")
                except Exception as e:
                    logger.warning(f"Не удалось добавить hashed_phone: {str(e)}")
            
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'encrypted_device_id'"))
            if not result.fetchone():
                try:
                    await conn.execute(text("ALTER TABLE users ADD COLUMN encrypted_device_id TEXT AFTER hashed_password"))
                    logger.info("Столбец encrypted_device_id добавлен")
                except Exception as e:
                    logger.warning(f"Не удалось добавить encrypted_device_id: {str(e)}")
            
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'e2e_key_updated'"))
            if not result.fetchone():
                try:
                    await conn.execute(text("ALTER TABLE users ADD COLUMN e2e_key_updated DATETIME DEFAULT CURRENT_TIMESTAMP AFTER encrypted_device_id"))
                    logger.info("Столбец e2e_key_updated добавлен")
                except Exception as e:
                    logger.warning(f"Не удалось добавить e2e_key_updated: {str(e)}")
            
            result = await conn.execute(text("SHOW COLUMNS FROM users LIKE 'last_activity'"))
            if not result.fetchone():
                try:
                    await conn.execute(text("ALTER TABLE users ADD COLUMN last_activity DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER e2e_key_updated"))
                    logger.info("Столбец last_activity добавлен")
                except Exception as e:
                    logger.warning(f"Не удалось добавить last_activity: {str(e)}")

            # Новые поля профиля
            for col, ddl in [
                ("encrypted_username", "ALTER TABLE users ADD COLUMN encrypted_username TEXT AFTER encrypted_nickname"),
                ("encrypted_bio", "ALTER TABLE users ADD COLUMN encrypted_bio TEXT AFTER encrypted_username"),
                ("encrypted_avatar", "ALTER TABLE users ADD COLUMN encrypted_avatar LONGTEXT AFTER encrypted_bio"),
                ("avatar_mime", "ALTER TABLE users ADD COLUMN avatar_mime VARCHAR(64) AFTER encrypted_avatar"),
                ("encrypted_avatar_mime", "ALTER TABLE users ADD COLUMN encrypted_avatar_mime TEXT AFTER avatar_mime"),
                ("encrypted_e2e_key_updated", "ALTER TABLE users ADD COLUMN encrypted_e2e_key_updated TEXT AFTER e2e_key_updated"),
                ("encrypted_last_activity", "ALTER TABLE users ADD COLUMN encrypted_last_activity TEXT AFTER last_activity"),
            ]:
                result = await conn.execute(text(f"SHOW COLUMNS FROM users LIKE '{col}'"))
                if not result.fetchone():
                    try:
                        await conn.execute(text(ddl))
                        logger.info(f"Столбец {col} добавлен")
                    except Exception as e:
                        logger.warning(f"Не удалось добавить {col}: {str(e)}")
            
            try:
                await conn.execute(text("""
                    UPDATE users 
                    SET e2e_key_updated = NOW(), last_activity = NOW() 
                    WHERE e2e_key_updated IS NULL OR last_activity IS NULL
                """))
                logger.info("Обновлены временные метки для существующих пользователей")
            except Exception as e:
                logger.warning(f"Не удалось обновить временные метки: {str(e)}")
            
            # Создаем все отсутствующие таблицы
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Схема базы данных синхронизирована")
            
            # Проверяем и создаем таблицы user_sessions, user_statuses, message_read_statuses
            for table_name in ['user_sessions', 'user_statuses', 'message_read_statuses']:
                result = await conn.execute(text(f"SHOW TABLES LIKE '{table_name}'"))
                if not result.fetchone():
                    logger.info(f"Таблица {table_name} не существует, создаем через metadata...")
                    await conn.run_sync(Base.metadata.create_all)
                    logger.info(f"Таблица {table_name} создана")
                else:
                    await ensure_innodb(conn, table_name)
            
            # Добавляем зашифрованные колонки для user_sessions
            user_sessions_encrypted_cols = [
                ("encrypted_device_type", "ALTER TABLE user_sessions ADD COLUMN encrypted_device_type TEXT AFTER device_type"),
                ("encrypted_device_name", "ALTER TABLE user_sessions ADD COLUMN encrypted_device_name TEXT AFTER device_name"),
                ("encrypted_ip_address", "ALTER TABLE user_sessions ADD COLUMN encrypted_ip_address TEXT AFTER ip_address"),
                ("encrypted_user_agent", "ALTER TABLE user_sessions ADD COLUMN encrypted_user_agent TEXT AFTER user_agent"),
                ("encrypted_created_at", "ALTER TABLE user_sessions ADD COLUMN encrypted_created_at TEXT AFTER created_at"),
                ("encrypted_last_activity", "ALTER TABLE user_sessions ADD COLUMN encrypted_last_activity TEXT AFTER last_activity"),
            ]
            for col, ddl in user_sessions_encrypted_cols:
                result = await conn.execute(text(f"SHOW COLUMNS FROM user_sessions LIKE '{col}'"))
                if not result.fetchone():
                    try:
                        await conn.execute(text(ddl))
                        logger.info(f"Столбец user_sessions.{col} добавлен")
                    except Exception as e:
                        logger.warning(f"Не удалось добавить user_sessions.{col}: {str(e)}")
            
            # Добавляем зашифрованные колонки для user_statuses
            user_statuses_encrypted_cols = [
                ("encrypted_last_seen", "ALTER TABLE user_statuses ADD COLUMN encrypted_last_seen TEXT AFTER last_seen"),
                ("encrypted_updated_at", "ALTER TABLE user_statuses ADD COLUMN encrypted_updated_at TEXT AFTER updated_at"),
            ]
            for col, ddl in user_statuses_encrypted_cols:
                result = await conn.execute(text(f"SHOW COLUMNS FROM user_statuses LIKE '{col}'"))
                if not result.fetchone():
                    try:
                        await conn.execute(text(ddl))
                        logger.info(f"Столбец user_statuses.{col} добавлен")
                    except Exception as e:
                        logger.warning(f"Не удалось добавить user_statuses.{col}: {str(e)}")
            
            # Добавляем зашифрованные колонки для message_read_statuses
            message_read_statuses_encrypted_cols = [
                ("encrypted_last_read_message_id", "ALTER TABLE message_read_statuses ADD COLUMN encrypted_last_read_message_id TEXT AFTER last_read_message_id"),
                ("encrypted_read_at", "ALTER TABLE message_read_statuses ADD COLUMN encrypted_read_at TEXT AFTER read_at"),
                ("encrypted_updated_at", "ALTER TABLE message_read_statuses ADD COLUMN encrypted_updated_at TEXT AFTER updated_at"),
            ]
            for col, ddl in message_read_statuses_encrypted_cols:
                result = await conn.execute(text(f"SHOW COLUMNS FROM message_read_statuses LIKE '{col}'"))
                if not result.fetchone():
                    try:
                        await conn.execute(text(ddl))
                        logger.info(f"Столбец message_read_statuses.{col} добавлен")
                    except Exception as e:
                        logger.warning(f"Не удалось добавить message_read_statuses.{col}: {str(e)}")
            
            # Добавляем зашифрованные колонки для chats
            chats_encrypted_cols = [
                ("encrypted_name", "ALTER TABLE chats ADD COLUMN encrypted_name TEXT AFTER name"),
                ("encrypted_created_at", "ALTER TABLE chats ADD COLUMN encrypted_created_at TEXT AFTER created_at"),
                ("encrypted_invite_code", "ALTER TABLE chats ADD COLUMN encrypted_invite_code TEXT AFTER invite_code"),
            ]
            for col, ddl in chats_encrypted_cols:
                result = await conn.execute(text(f"SHOW COLUMNS FROM chats LIKE '{col}'"))
                if not result.fetchone():
                    try:
                        await conn.execute(text(ddl))
                        logger.info(f"Столбец chats.{col} добавлен")
                    except Exception as e:
                        logger.warning(f"Не удалось добавить chats.{col}: {str(e)}")
            
            # Добавляем зашифрованные колонки для chat_members
            chat_members_encrypted_cols = [
                ("encrypted_joined_at", "ALTER TABLE chat_members ADD COLUMN encrypted_joined_at TEXT AFTER joined_at"),
            ]
            for col, ddl in chat_members_encrypted_cols:
                result = await conn.execute(text(f"SHOW COLUMNS FROM chat_members LIKE '{col}'"))
                if not result.fetchone():
                    try:
                        await conn.execute(text(ddl))
                        logger.info(f"Столбец chat_members.{col} добавлен")
                    except Exception as e:
                        logger.warning(f"Не удалось добавить chat_members.{col}: {str(e)}")

        async with database.AsyncSessionLocal() as session:
            async with session.begin():
                try:
                    stmt = select(User).filter(User.hashed_phone.is_(None))
                    result = await session.execute(stmt)
                    users = result.scalars().all()
                    updated_count = 0
                    for user in users:
                        if user.encrypted_phone:
                            try:
                                phone = decrypt_data(user.encrypted_phone)
                                if phone is None:
                                    logger.warning(f"Не удалось расшифровать телефон для {user.unique_id}")
                                    continue
                                user.hashed_phone = hashlib.sha256(phone.encode()).hexdigest()
                                updated_count += 1
                                logger.debug(f"Обновлен hashed_phone для пользователя {user.unique_id}")
                            except Exception as e:
                                logger.warning(f"Ошибка расшифровки телефона для пользователя {user.unique_id}: {str(e)}")
                    
                    logger.info(f"Обновлено {updated_count} записей с hashed_phone")
                except Exception as e:
                    logger.warning(f"Ошибка обновления hashed_phone: {str(e)}")
        
        # Generate unique_ids for existing users without them
        async with database.AsyncSessionLocal() as session:
            async with session.begin():
                try:
                    stmt = select(User).filter(User.unique_id.is_(None))
                    result = await session.execute(stmt)
                    users = result.scalars().all()
                    generated_count = 0
                    for user in users:
                        uid = await generate_unique_id(session)
                        user.unique_id = uid
                        generated_count += 1
                        logger.debug(f"Сгенерирован unique_id {uid} для пользователя id={user.id}")
                    logger.info(f"Сгенерировано {generated_count} unique_id для существующих пользователей")
                except Exception as e:
                    logger.warning(f"Ошибка генерации unique_id: {str(e)}")
        
        logger.info("Инициализация базы данных завершена успешно")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка инициализации базы данных: {str(e)}")
        return False

async def reconnect_db():
    if not await init_db():
        logger.error("Переподключение к БД не удалось.")

async def check_ssl_update():
    global last_cert_mtime, last_key_mtime
    try:
        cert_mtime = os.path.getmtime(SSL_CERTFILE)
        key_mtime = os.path.getmtime(SSL_KEYFILE)
        if cert_mtime != last_cert_mtime or key_mtime != last_key_mtime:
            logger.info("Обнаружены изменения в SSL сертификатах")
            last_cert_mtime = cert_mtime
            last_key_mtime = key_mtime
    except Exception as e:
        logger.error(f"Ошибка проверки SSL обновлений: {str(e)}")

async def rotate_encryption_key():
    """Ротация ENCRYPTION_KEY раз в месяц: генерируем новый, мигрируем данные в БД, обновляем .env"""
    try:
        # Генерируем новый ключ
        new_key_bytes = secrets.token_bytes(32)
        new_key_str = base64.urlsafe_b64encode(new_key_bytes).decode()
        
        # Мигрируем все encrypted поля в users
        async with database.AsyncSessionLocal() as session:
            async with session.begin():
                stmt = select(User)
                result = await session.execute(stmt)
                users = result.scalars().all()
                migrated = 0
                for user in users:
                    fields_to_migrate = [
                        ('encrypted_phone', user.encrypted_phone),
                        ('encrypted_name', user.encrypted_name),
                        ('encrypted_nickname', user.encrypted_nickname),
                        ('encrypted_device_id', user.encrypted_device_id)
                    ]
                    for field_name, enc_value in fields_to_migrate:
                        if enc_value:
                            old_plain = decrypt_data(enc_value)  # Используем старый ключ
                            if old_plain:
                                new_enc = encrypt_data(old_plain, new_key_bytes)  # Шифруем новым
                                setattr(user, field_name, new_enc)
                                migrated += 1
                    await session.flush()
                logger.info(f"Мигрировано {migrated} полей users под новый ENCRYPTION_KEY")
        
        # Мигрируем e2e_keys (отдельная сессия)
        async with database.AsyncSessionLocal() as session:
            async with session.begin():
                stmt = select(E2EKey)
                result = await session.execute(stmt)
                e2ekeys = result.scalars().all()
                migrated_e2e = 0
                for e2ek in e2ekeys:
                    if e2ek.encrypted_public_key:
                        old_plain = decrypt_data(e2ek.encrypted_public_key)
                        if old_plain:
                            e2ek.encrypted_public_key = encrypt_data(old_plain, new_key_bytes)
                            migrated_e2e += 1
                logger.info(f"Мигрировано {migrated_e2e} e2e_keys под новый ENCRYPTION_KEY")
        
        # Обновляем .env файл (создаем при отсутствии)
        try:
            with open('.env', 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            lines = []
        wrote_key = False
        new_lines = []
        for line in lines:
            if line.startswith('ENCRYPTION_KEY_STR='):
                new_lines.append(f'ENCRYPTION_KEY_STR={new_key_str}\n')
                wrote_key = True
            else:
                new_lines.append(line)
        if not wrote_key:
            new_lines.append(f'ENCRYPTION_KEY_STR={new_key_str}\n')
        with open('.env', 'w') as f:
            f.writelines(new_lines)
        logger.info("ENCRYPTION_KEY_STR обновлен/создан в .env")
        
        # Перезагружаем глобальный ключ
        global ENCRYPTION_KEY
        ENCRYPTION_KEY = new_key_bytes
        logger.info("Ротация ENCRYPTION_KEY завершена успешно")
    except Exception as e:
        logger.error(f"Ошибка ротации ENCRYPTION_KEY: {str(e)}")

async def setup_db_and_scheduler():
    global initialized
    if initialized:
        return
    await database.init_db_connections()
    try:
        await database.redis_client.ping()
    except Exception as e:
        logger.error(f"Redis ping failed: {str(e)}")
        raise
    await init_db()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(reconnect_db, IntervalTrigger(minutes=5))
    scheduler.add_job(clean_redis, IntervalTrigger(hours=1))
    scheduler.add_job(check_ssl_update, IntervalTrigger(hours=24))
    scheduler.add_job(rotate_encryption_key, CronTrigger(day=1, hour=2, minute=0))  # Раз в месяц, 1-го числа в 2:00
    # Рассылка пушей для оффлайн пользователей раз в минуту
    scheduler.add_job(process_offline_push_queue, IntervalTrigger(minutes=1))
    scheduler.start()
    logger.info("Планировщик запущен.")
    # Подключаем роутеры после того, как доступны зависимости
    app.include_router(build_sessions_router(get_db, get_current_user, User))
    app.include_router(build_scheduler_router(get_db, get_current_user, User, database.redis_client))
    app.include_router(build_devices_router(get_db, get_current_user, database.redis_client))
    app.include_router(build_chats_router(get_db, get_current_user, {"Chat": Chat, "ChatMember": ChatMember, "User": User}))
    app.include_router(build_avatars_router(get_db, get_current_user, encrypt_data))
    app.include_router(build_chat_messages_router(get_db, get_current_user, database.redis_client))
    app.include_router(build_chat_members_router(get_db, get_current_user, {"Chat": Chat, "ChatMember": ChatMember, "User": User}))
    app.include_router(build_invites_router(get_db, get_current_user, {"Chat": Chat, "ChatMember": ChatMember, "User": User}, database.redis_client))
    app.include_router(build_message_mgmt_router(get_db, get_current_user, database.redis_client))
    app.include_router(build_user_status_router(get_db, get_current_user, User))
    initialized = True

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await setup_db_and_scheduler()
    except Exception as e:
        logger.error(f"Ошибка инициализации при старте приложения: {str(e)}")
        raise
    yield

# Register lifespan handler to avoid deprecated on_event startup
app.router.lifespan_context = lifespan

async def clean_redis():
    try:
        patterns = ["otp:*", "pending_sub:*", "secret_sub:*", "rate_limit:*", "block:*", "ws_message:*", "failed_login:*", "call_pending:*", "jwt_blacklist:*", "typing:*"]
        for pattern in patterns:
            keys = await database.redis_client.keys(pattern)
            for key in keys:
                ttl = await database.redis_client.ttl(key)
                if ttl < 0:
                    await database.redis_client.delete(key)
                    logger.debug(f"Удален ключ Redis: {key}")
        logger.debug(f"Очищены устаревшие ключи Redis: {patterns}")
    except Exception as e:
        logger.error(f"Ошибка очистки Redis: {str(e)}")

async def get_db() -> AsyncSession:
    session = database.AsyncSessionLocal()
    try:
        yield session
    except HTTPException as e:
        await session.rollback()  
        raise
    except Exception as e:
        await session.rollback()
        logger.error(f"Ошибка базы данных: {str(e)}")
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера. Пожалуйста, попробуйте позже.")
    finally:
        await session.close()

class RegisterRequest(BaseModel):
    phone: str
    name: str
    nickname: str
    password: str
    device_id: str
    public_e2e_key: str  # Добавлено: публичный ключ клиента для true E2E (PEM string)

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
        v = re.sub(r'<[^>]*>', '', v)
        if len(v) < 1 or len(v) > 50 or not re.match(r'^[\w\s-]*$', v):
            raise ValueError('Недопустимое имя или никнейм. Длина от 1 до 50 символов, только буквы, цифры, пробелы, тире и подчеркивания.')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 128:
            raise ValueError('Пароль должен быть от 8 до 128 символов.')
        return v

    @field_validator('device_id')
    @classmethod
    def validate_device_id(cls, v):
        if len(v) != 16 or not re.match(r'^[0-9a-fA-F]+$', v):
            raise ValueError('Device ID должен быть 16-значной hex-строкой (64 бита).')
        return v

    @field_validator('public_e2e_key')
    @classmethod
    def validate_public_e2e_key(cls, v):
        try:
            # Проверяем, что это валидный PEM public key
            public_key_obj = serialization.load_pem_public_key(v.encode(), backend=default_backend())
            if not isinstance(public_key_obj, rsa.RSAPublicKey):
                raise ValueError('Недопустимый публичный ключ E2E.')
            return v
        except Exception:
            raise ValueError('Публичный ключ E2E должен быть в формате PEM для RSA.')

class LoginRequest(BaseModel):
    identifier: str
    password: str
    device_id: str
    device_token: Optional[str] = None
    public_e2e_key: Optional[str] = None  # Добавлено: опционально обновить public key при логине

    @field_validator('device_id')
    @classmethod
    def validate_device_id(cls, v):
        if len(v) != 16 or not re.match(r'^[0-9a-fA-F]+$', v):
            raise ValueError('Device ID должен быть 16-значной hex-строкой (64 бита).')
        return v

    @field_validator('public_e2e_key')
    @classmethod
    def validate_public_e2e_key(cls, v):
        if v:
            try:
                public_key_obj = serialization.load_pem_public_key(v.encode(), backend=default_backend())
                if not isinstance(public_key_obj, rsa.RSAPublicKey):
                    raise ValueError('Недопустимый публичный ключ E2E.')
                return v
            except Exception:
                raise ValueError('Публичный ключ E2E должен быть в формате PEM для RSA.')
        return v

class SubscribeRequest(BaseModel):
    target_id: str
    secret: bool = False
    csrf_token: str

    @field_validator('csrf_token')
    @classmethod
    def validate_csrf(cls, v):
        return v

class ProfileUpdateRequest(BaseModel):
    name: Optional[str] = None
    nickname: Optional[str] = None
    username: Optional[str] = None
    bio: Optional[str] = None
    password: Optional[str] = None

    @field_validator('name', 'nickname')
    @classmethod
    def validate_names(cls, v):
        if v is not None:
            v = re.sub(r'<[^>]*>', '', v)
            if len(v) < 1 or len(v) > 50 or not re.match(r'^[\w\s-]*$', v):
                raise ValueError('Недопустимое имя или никнейм.')
        return v

    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if v is not None and (len(v) < 8 or len(v) > 128):
            raise ValueError('Пароль должен быть от 8 до 128 символов.')
        return v


async def ensure_redis():
    if database.redis_client is None:
        await database.init_db_connections()

async def check_rate_limit(request: Request):
    await ensure_redis()
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', 'unknown')
    ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
    try:
        ipaddress.ip_address(client_ip)
    except Exception:
        logger.warning(f"Неверный формат IP: {client_ip}, user-agent: {mask_sensitive(user_agent)}")
        raise HTTPException(status_code=400, detail="Неверный IP-адрес")
    rate_key = f"rate_limit:{client_ip}:{ua_hash}"
    block_key = f"block:{client_ip}:{ua_hash}"
    if await database.redis_client.exists(block_key):
        ttl = await database.redis_client.ttl(block_key)
        logger.warning(f"IP {client_ip} заблокирован, осталось {ttl} секунд, user-agent: {mask_sensitive(user_agent)}")
        raise HTTPException(status_code=429, detail=f"IP {client_ip} заблокирован на {ttl/60:.1f} минут. Подождите и попробуйте снова.")
    count = await database.redis_client.incr(rate_key)
    if count == 1:
        await database.redis_client.expire(rate_key, RATE_LIMIT_PERIOD)
    if count > RATE_LIMIT_CALLS:
        await database.redis_client.set(block_key, 1, ex=BLOCK_PERIOD)
        await database.redis_client.delete(rate_key)
        logger.warning(f"IP {client_ip} превысил лимит запросов: {count}, user-agent: {mask_sensitive(user_agent)}")
        raise HTTPException(status_code=429, detail=f"Лимит запросов превышен ({RATE_LIMIT_CALLS} за {RATE_LIMIT_PERIOD} секунд). Подождите и попробуйте снова.")
    logger.debug(f"Проверка лимита для IP {client_ip}, user-agent={mask_sensitive(user_agent)}, текущий счетчик: {count}")

async def check_ws_rate_limit(user_id: str, client_ip: str):
    await ensure_redis()
    ws_rate_key = f"ws_rate:{user_id}:{client_ip}"
    count = await database.redis_client.incr(ws_rate_key)
    if count == 1:
        await database.redis_client.expire(ws_rate_key, WS_RATE_LIMIT_PERIOD)
    if count > WS_RATE_LIMIT_MESSAGES:
        logger.warning(f"WebSocket rate limit превышен для {user_id}, IP={client_ip}")
        raise HTTPException(status_code=429, detail="Лимит сообщений превышен. Подождите и попробуйте снова.")

async def check_ws_connections_per_ip(client_ip: str):
    await ensure_redis()
    ip_key = f"ws_ip_connections:{client_ip}"
    count = await database.redis_client.incr(ip_key)
    if count == 1:
        await database.redis_client.expire(ip_key, 3600)
    if count > WS_MAX_CONNECTIONS_PER_IP:
        logger.warning(f"Максимум подключений превышен для IP {client_ip}")
        raise HTTPException(status_code=429, detail="Слишком много подключений с этого IP. Подождите и попробуйте снова.")

async def check_failed_logins(client_ip: str):
    await ensure_redis()
    failed_key = f"failed_login:{client_ip}"
    block_key = f"block:{client_ip}"
    if await database.redis_client.exists(block_key):
        ttl = await database.redis_client.ttl(block_key)
        raise HTTPException(status_code=429, detail=f"IP {client_ip} заблокирован из-за неудачных попыток входа на {ttl/60:.1f} минут. Подождите и попробуйте снова.")
    count = await database.redis_client.get(failed_key)
    count = int(count) if count else 0
    if count >= FAILED_LOGIN_LIMIT:
        await database.redis_client.set(block_key, 1, ex=FAILED_LOGIN_BLOCK_PERIOD)
        await database.redis_client.delete(failed_key)
        logger.warning(f"IP {client_ip} заблокирован из-за {count} неудачных попыток входа")
        raise HTTPException(status_code=429, detail=f"Слишком много неудачных попыток входа. Заблокировано на {FAILED_LOGIN_BLOCK_PERIOD/60:.1f} минут. Подождите и попробуйте снова.")

async def increment_failed_login(client_ip: str):
    await ensure_redis()
    failed_key = f"failed_login:{client_ip}"
    count = await database.redis_client.incr(failed_key)
    if count == 1:
        await database.redis_client.expire(failed_key, 3600)

async def reset_failed_login(client_ip: str):
    await ensure_redis()
    failed_key = f"failed_login:{client_ip}"
    await database.redis_client.delete(failed_key)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', 'unknown')
    logger.debug(f"HTTP запрос: IP={client_ip}, user-agent={mask_sensitive(user_agent)}, путь={request.url.path}")
    is_login_register = request.url.path in ["/login", "/register"]
    try:
        await check_rate_limit(request)
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
    if is_login_register:
        try:
            await check_failed_logins(client_ip)
        except HTTPException as e:
            return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
    try:
        response = await call_next(request)
        if response.status_code == 200 and is_login_register:
            await reset_failed_login(client_ip)
        return response
    except HTTPException as e:
        if e.status_code in [401, 400, 404] and is_login_register:
            await increment_failed_login(client_ip)
        return JSONResponse(status_code=e.status_code, content={"detail": e.detail})
    except Exception as e:
        logger.error(f"Неожиданная ошибка в middleware: {str(e)}")
        return JSONResponse(status_code=500, content={"detail": "Внутренняя ошибка сервера. Пожалуйста, попробуйте позже."})

# Удалены e2e_encrypt/decrypt, так как true E2E: шифрование на клиенте
# Добавлена функция для верификации подписи (опционально, для улучшения)
def verify_signature(message: bytes, signature: bytes, public_key_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def encrypt_data(data: str, key: bytes = ENCRYPTION_KEY) -> str:  # Изменено: опциональный key для ротации
    try:
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
        return base64.urlsafe_b64encode(nonce + ciphertext + encryptor.tag).decode()
    except Exception as e:
        logger.error(f"Ошибка шифрования данных: {str(e)}")
        return None

def decrypt_data(enc_data: str, key: bytes = ENCRYPTION_KEY) -> str:  # Изменено: опциональный key для ротации
    if enc_data is None:
        return None
    try:
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

async def generate_unique_id(db_session: AsyncSession) -> str:
    await ensure_redis()
    lock_key = "unique_id_lock"
    while True:
        acquired = await database.redis_client.setnx(lock_key, 1)
        if acquired:
            await database.redis_client.expire(lock_key, 5)
            try:
                for _ in range(10):
                    uid = str(random.randint(10000000, 99999999))
                    stmt = select(User).filter(User.unique_id == uid)
                    result = await db_session.execute(stmt)
                    if not result.scalar_one_or_none():
                        logger.debug(f"Сгенерирован уникальный ID: {uid}")
                        return uid
                logger.error("Не удалось сгенерировать уникальный ID")
                raise HTTPException(status_code=500, detail="Ошибка генерации уникального ID. Попробуйте заново.")
            finally:
                await database.redis_client.delete(lock_key)
            break
        else:
            await asyncio.sleep(0.1)

@app.post("/register")
async def register(req: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', 'unknown')
    logger.info(f"Запрос регистрации: IP={client_ip}, user-agent={mask_sensitive(user_agent)}, phone={mask_sensitive(req.phone)}, device_id={mask_sensitive(req.device_id)}")
    for plugin in plugins:
        await plugin.execute_hook('pre_register', req)
    async with db.begin():
        try:
            hashed_phone = hashlib.sha256(req.phone.encode()).hexdigest()
            stmt = select(User).filter(User.hashed_phone == hashed_phone)
            result = await db.execute(stmt)
            if result.scalar_one_or_none():
                logger.warning(f"Телефон {mask_sensitive(req.phone)} уже зарегистрирован, IP={client_ip}")
                raise HTTPException(status_code=400, detail="Телефон уже зарегистрирован.")
            hashed_pw = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
            enc_device_id = encrypt_data(req.device_id)
            if enc_device_id is None:
                logger.error(f"Не удалось зашифровать device_id, IP={client_ip}")
                raise HTTPException(status_code=500, detail="Ошибка создания ключа шифрования. Попробуйте заново.")
            
            now = datetime.utcnow()
            user = User(
                unique_id=await generate_unique_id(db),
                hashed_phone=hashed_phone,
                encrypted_phone=encrypt_data(req.phone),
                encrypted_name=encrypt_data(req.name),
                encrypted_nickname=encrypt_data(req.nickname),
                hashed_password=hashed_pw,
                encrypted_device_id=enc_device_id,
                e2e_key_updated=now,
                last_activity=now
            )
            db.add(user)
            await db.flush()
            # Добавляем encrypted e2e key
            enc_public_key = encrypt_data(req.public_e2e_key)
            if enc_public_key is None:
                raise HTTPException(status_code=500, detail="Ошибка шифрования E2E ключа.")
            e2e_key = E2EKey(user_id=user.id, encrypted_public_key=enc_public_key, updated_at=now)
            db.add(e2e_key)
            logger.info(f"Пользователь зарегистрирован: {user.unique_id}, device_id={mask_sensitive(req.device_id)}, IP={client_ip}")
            for plugin in plugins:
                await plugin.execute_hook('post_register', user)
            return {
                "unique_id": user.unique_id,
                "public_e2e_key": req.public_e2e_key,  # Возвращаем plaintext
                "phone": req.phone,
                "name": req.name,
                "nickname": req.nickname,
                "device_id": req.device_id
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Ошибка регистрации для {mask_sensitive(req.phone)}: {str(e)}, IP={client_ip}")
            raise HTTPException(status_code=500, detail=f"Ошибка регистрации: {str(e)}. Попробуйте заново.")

@app.post("/login")
async def login(req: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host
    user_agent = request.headers.get('user-agent', 'unknown')
    logger.info(f"Запрос входа: IP={client_ip}, user-agent={mask_sensitive(user_agent)}, identifier={mask_sensitive(req.identifier)}, device_id={mask_sensitive(req.device_id)}")
    for plugin in plugins:
        await plugin.execute_hook('pre_login', req)
    async with db.begin():
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
                logger.info(f"Пользователь с идентификатором {mask_sensitive(identifier)} не найден, IP={client_ip}")
                raise HTTPException(status_code=401, detail="Пользователь не найден.")
            # Auto-login по устройству: валидный device_token позволяет войти без пароля
            autologin_ok = False
            if req.device_token:
                key = f"device:{user.unique_id}:{req.device_id}"
                stored = await database.redis_client.get(key)
                autologin_ok = stored == req.device_token
                if autologin_ok:
                    logger.info(f"Auto-login успешен для {user.unique_id}")
            if not autologin_ok:
                if not bcrypt.checkpw(req.password.encode(), user.hashed_password.encode()):
                    logger.warning(f"Неверный пароль для {mask_sensitive(identifier)}, IP={client_ip}")
                    raise HTTPException(status_code=401, detail="Неверный пароль.")
            # Ротация: если ключ старше 180 дней, клиент должен обновить
            stmt_e2e = select(E2EKey).filter(E2EKey.user_id == user.id)
            result_e2e = await db.execute(stmt_e2e)
            e2ek = result_e2e.scalar_one_or_none()
            if e2ek and (datetime.utcnow() - e2ek.updated_at > timedelta(days=E2E_KEY_ROTATION_DAYS)) and not req.public_e2e_key:
                logger.warning(f"e2e_key устарел для {user.unique_id}, клиент должен обновить")
            if req.public_e2e_key:
                # Обновляем e2e key
                try:
                    serialization.load_pem_public_key(req.public_e2e_key.encode(), backend=default_backend())
                    enc_public_key = encrypt_data(req.public_e2e_key)
                    if enc_public_key is None:
                        raise HTTPException(status_code=500, detail="Ошибка шифрования E2E ключа.")
                    if e2ek:
                        e2ek.encrypted_public_key = enc_public_key
                        e2ek.updated_at = datetime.utcnow()
                    else:
                        e2ek = E2EKey(user_id=user.id, encrypted_public_key=enc_public_key, updated_at=datetime.utcnow())
                        db.add(e2ek)
                    logger.info(f"Обновлен e2e_key для {user.unique_id}")
                except Exception as e:
                    logger.warning(f"Неверный новый public_e2e_key для {user.unique_id}: {str(e)}")
            if req.device_id:
                user.encrypted_device_id = encrypt_data(req.device_id)
                logger.info(f"Обновлен device_id для {user.unique_id} на {mask_sensitive(req.device_id)}, IP={client_ip}")
            
            # Generate JWT token
            token_data = await create_access_token({"sub": str(user.unique_id)})
            token = token_data if isinstance(token_data, str) else token_data.get('access_token', token_data)
            
            # Извлекаем JTI из токена для создания сессии
            import jwt as jwt_lib
            try:
                decoded = jwt_lib.decode(token, options={"verify_signature": False})
                jti = decoded.get('jti')
            except:
                jti = secrets.token_urlsafe(32)
            
            # Generate CSRF token
            csrf_token = secrets.token_urlsafe(32)
            csrf_key = f"csrf:{user.unique_id}"
            await database.redis_client.set(csrf_key, csrf_token, ex=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
            
            # Generate device_token for auto-login
            device_token = secrets.token_urlsafe(32)
            device_key = f"device:{user.unique_id}:{req.device_id}"
            await database.redis_client.set(device_key, device_token, ex=30*24*3600)  # 30 days
            logger.info(f"Generated device_token for {user.unique_id}, device={mask_sensitive(req.device_id)}")
            
            # Определяем тип устройства по User-Agent
            device_type = "unknown"
            device_name = None
            if user_agent:
                ua_lower = user_agent.lower()
                if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
                    device_type = "phone"
                elif "tablet" in ua_lower or "ipad" in ua_lower:
                    device_type = "tablet"
                elif "electron" in ua_lower or "desktop" in ua_lower:
                    device_type = "pc"
                else:
                    device_type = "web"
                device_name = user_agent[:100] if len(user_agent) > 100 else user_agent
            
            # Создаем запись сессии
            new_session = UserSession(
                user_id=user.id,
                session_token=jti,
                device_type=device_type,
                device_name=device_name,
                ip_address=client_ip,
                user_agent=user_agent[:500] if user_agent and len(user_agent) > 500 else user_agent,
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow(),
                is_active=True
            )
            db.add(new_session)
            
            user.last_activity = datetime.utcnow()
            db.add(user)
            logger.info(f"Пользователь вошел: {user.unique_id}, device_id={mask_sensitive(req.device_id)}, IP={client_ip}")
            for plugin in plugins:
                await plugin.execute_hook('post_login', user)
            public_e2e = decrypt_data(e2ek.encrypted_public_key) if e2ek else None
            return {
                "access_token": token,
                "token_type": "bearer",
                "csrf_token": csrf_token,
                "device_token": device_token,
                "public_e2e_key": public_e2e,
                "unique_id": user.unique_id,
                "phone": decrypt_data(user.encrypted_phone),
                "name": decrypt_data(user.encrypted_name),
                "nickname": decrypt_data(user.encrypted_nickname),
                "device_id": req.device_id
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Ошибка входа для {mask_sensitive(req.identifier)}: {str(e)}, IP={client_ip}")
            raise HTTPException(status_code=500, detail=f"Ошибка входа: {str(e)}. Попробуйте заново.")

from app.auth import get_public_key_pem

@app.get("/public_key")
async def get_public_key():
    logger.debug("Запрос публичного ключа (без авторизации)")
    return {"public_key": get_public_key_pem()}

class PublicKeyUpdate(BaseModel):
    public_e2e_key: str

@app.post("/e2e/public_key")
async def set_public_key(req: PublicKeyUpdate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    async with db.begin():
        try:
            serialization.load_pem_public_key(req.public_e2e_key.encode(), backend=default_backend())
            stmt = select(E2EKey).filter(E2EKey.user_id == current_user.id)
            result = await db.execute(stmt)
            e2ek = result.scalar_one_or_none()
            enc = encrypt_data(req.public_e2e_key)
            if not enc:
                raise HTTPException(500, detail="Ошибка шифрования ключа")
            if e2ek:
                e2ek.encrypted_public_key = enc
                e2ek.updated_at = datetime.utcnow()
                db.add(e2ek)
            else:
                db.add(E2EKey(user_id=current_user.id, encrypted_public_key=enc, updated_at=datetime.utcnow()))
            logger.info(f"Публичный E2E ключ обновлен для {current_user.unique_id}")
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Ошибка обновления публичного ключа для {current_user.unique_id}: {str(e)}")
            raise HTTPException(500, detail="Ошибка обновления ключа")

@app.get("/encryption_public_key")
async def get_encryption_public_key():
    # Синоним для клиента, чтобы получить публичный ключ шифрования сервера
    logger.debug("Запрос публичного ключа шифрования (alias)")
    return {"public_key": get_public_key_pem()}

@app.get("/vapid_public_key")
async def get_vapid_public_key():
    # Для Web Push клиентов: отдаем публичный VAPID ключ из переменных окружения
    vapid_public_key = os.getenv('VAPID_PUBLIC_KEY')
    if not vapid_public_key:
        raise HTTPException(status_code=404, detail="VAPID_PUBLIC_KEY не настроен")
    return {"vapid_public_key": vapid_public_key}

class SecretKeyPayload(BaseModel):
    ciphertext: str  # base64/json от клиента (envelope)

@app.post("/e2e/secret_key")
async def save_secret_key(payload: SecretKeyPayload, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    async with db.begin():
        try:
            if not payload.ciphertext or len(payload.ciphertext) < 16:
                raise HTTPException(400, detail="Неверный формат секретного ключа")
            stmt = select(SecretE2EKey).filter(SecretE2EKey.user_id == current_user.id)
            result = await db.execute(stmt)
            rec = result.scalar_one_or_none()
            if rec:
                rec.client_encrypted_secret = payload.ciphertext
                rec.updated_at = datetime.utcnow()
                db.add(rec)
            else:
                rec = SecretE2EKey(user_id=current_user.id, client_encrypted_secret=payload.ciphertext, updated_at=datetime.utcnow())
                db.add(rec)
            current_user.last_activity = datetime.utcnow()
            await db.merge(current_user)
            logger.info(f"Секретный E2E ключ сохранен для {current_user.unique_id}")
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Ошибка сохранения секретного ключа для {current_user.unique_id}: {str(e)}")
            raise HTTPException(500, detail="Ошибка сохранения ключа")

@app.get("/e2e/secret_key")
async def get_secret_key(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    async with db.begin():
        try:
            stmt = select(SecretE2EKey).filter(SecretE2EKey.user_id == current_user.id)
            result = await db.execute(stmt)
            rec = result.scalar_one_or_none()
            if not rec:
                return {"ciphertext": None}
            return {"ciphertext": rec.client_encrypted_secret, "updated_at": rec.updated_at.isoformat()}
        except Exception as e:
            logger.error(f"Ошибка получения секретного ключа для {current_user.unique_id}: {str(e)}")
            raise HTTPException(500, detail="Ошибка получения ключа")

@app.get("/csrf_token")
async def get_csrf_token(current_user: User = Depends(get_current_user)):
    csrf_key = f"csrf:{current_user.unique_id}"
    csrf_token = await database.redis_client.get(csrf_key)
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        await database.redis_client.set(csrf_key, csrf_token, ex=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        logger.debug(f"Сгенерирован новый CSRF токен для {current_user.unique_id}")
    return {"csrf_token": csrf_token}

@app.post("/register_push")
async def register_push(payload: dict, current_user: User = Depends(get_current_user)):
    try:
        if not isinstance(payload, dict):
            raise HTTPException(status_code=400, detail="Неверный формат данных")
        platform = (payload.get('platform') or 'web').lower()
        subscription = payload.get('subscription')
        # Validate Web Push subscription
        if platform == 'web':
            from app.push import validate_subscription
            validate_subscription(subscription)
            value = {
                "platform": platform,
                "subscription": subscription,
                "updated_at": datetime.utcnow().isoformat()
            }
        else:
            # Fallback for mobile platforms using token
            push_token = payload.get('push_token')
            if not push_token:
                raise HTTPException(status_code=400, detail="Отсутствует push_token для платформы")
            value = {
                "platform": platform,
                "endpoint": push_token,
                "updated_at": datetime.utcnow().isoformat()
            }
        key = f"push:{current_user.unique_id}"
        await database.redis_client.set(key, json.dumps(value), ex=30*24*3600)
        logger.info(f"Push-подписка сохранена для {current_user.unique_id}")
        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Ошибка регистрации push-подписки: {str(e)}")
        raise HTTPException(status_code=500, detail="Ошибка регистрации push-подписки")

@app.get("/ice_servers")
async def get_ice_servers(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    async with db.begin():
        try:
            current_user.last_activity = datetime.utcnow()
            await db.merge(current_user)
            logger.debug(f"Запрос ICE-серверов от {current_user.unique_id}")
            return {"ice_servers": ICE_SERVERS}
        except Exception as e:
            logger.error(f"Ошибка получения ICE-серверов для {current_user.unique_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка получения ICE-серверов. Попробуйте заново.")

@app.post("/subscribe")
async def subscribe(req: SubscribeRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    csrf_key = f"csrf:{current_user.unique_id}"
    stored_csrf = await database.redis_client.get(csrf_key)
    if not stored_csrf or req.csrf_token != stored_csrf:
        logger.warning(f"Неверный CSRF для {current_user.unique_id}")
        raise HTTPException(status_code=403, detail="Неверный CSRF-токен.")
    for plugin in plugins:
        await plugin.execute_hook('pre_subscribe', req, current_user)
    async with db.begin():
        try:
            stmt = select(User).filter(User.unique_id == req.target_id)
            result = await db.execute(stmt)
            target = result.scalar_one_or_none()
            if not target:
                logger.error(f"Целевой пользователь {req.target_id} не найден для подписки от {current_user.unique_id}")
                raise HTTPException(status_code=404, detail="Целевой пользователь не найден.")
            if req.target_id == str(current_user.unique_id):
                logger.warning(f"Попытка подписки на себя: {current_user.unique_id}")
                raise HTTPException(400, detail="Нельзя подписаться на себя.")
            # Проверяем, нет ли уже подписки
            stmt_sub = select(Subscription).filter(Subscription.user_id == current_user.id, Subscription.target_id == target.id)
            result_sub = await db.execute(stmt_sub)
            if result_sub.scalar_one_or_none():
                logger.warning(f"Уже есть подписка на {req.target_id} пользователем {current_user.unique_id}")
                raise HTTPException(400, detail="Уже подписаны на этого пользователя.")
            sub = Subscription(user_id=current_user.id, target_id=target.id, status='pending')
            db.add(sub)
            if req.secret:
                await database.redis_client.set(f"secret_sub:{current_user.unique_id}:{req.target_id}", 1, ex=3600)
            notification = json.dumps({
                "type": "subscription_request",
                "from_id": current_user.unique_id,
                "from_phone": decrypt_data(current_user.encrypted_phone),
                "secret": req.secret
            })
            message_key = f"ws_message:{req.target_id}"
            await database.redis_client.rpush(message_key, notification)
            await database.redis_client.expire(message_key, 86400)
            if str(target.unique_id) in active_connections:
                try:
                    await active_connections[str(target.unique_id)]['websocket'].send(notification)
                    logger.info(f"Отправлено сообщение от {current_user.unique_id} к {req.target_id}")
                except Exception as e:
                    logger.warning(f"Не удалось отправить сообщение {req.target_id}: {str(e)}")
            else:
                logger.warning(f"Пользователь {req.target_id} не в сети")
            current_user.last_activity = datetime.utcnow()
            await db.merge(current_user)
            logger.info(f"Запрос на подписку: {current_user.unique_id} -> {req.target_id} (secret: {req.secret})")
            for plugin in plugins:
                await plugin.execute_hook('post_subscribe', req, current_user, target)
            return {"status": "subscription_requested"}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Ошибка подписки для {current_user.unique_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка подписки. Попробуйте заново.")

@app.post("/confirm_subscribe")
async def confirm_subscribe(req: SubscribeRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    csrf_key = f"csrf:{current_user.unique_id}"
    stored_csrf = await database.redis_client.get(csrf_key)
    if not stored_csrf or req.csrf_token != stored_csrf:
        logger.warning(f"Неверный CSRF для {current_user.unique_id}")
        raise HTTPException(status_code=403, detail="Неверный CSRF-токен.")
    async with db.begin():
        try:
            # Get requester
            stmt_requester = select(User).filter(User.unique_id == req.target_id)
            result_requester = await db.execute(stmt_requester)
            requester = result_requester.scalar_one_or_none()
            if not requester:
                raise HTTPException(status_code=404, detail="Requester not found.")
            # Проверяем pending подписку
            stmt_pending = select(Subscription).filter(
                Subscription.user_id == requester.id,
                Subscription.target_id == current_user.id,
                Subscription.status == 'pending'
            )
            result_pending = await db.execute(stmt_pending)
            pending_sub = result_pending.scalar_one_or_none()
            if not pending_sub:
                logger.warning(f"Нет ожидающего запроса от {req.target_id} для {current_user.unique_id}")
                raise HTTPException(400, detail="Нет ожидающего запроса на подписку.")
            pending_sub.status = 'accepted'
            # Добавляем обратную подписку
            reverse_sub = Subscription(user_id=current_user.id, target_id=requester.id, status='accepted')
            db.add(reverse_sub)
            current_user.last_activity = datetime.utcnow()
            await db.merge(current_user)
            target = requester
            if target:
                target.last_activity = datetime.utcnow()
                await db.merge(target)
            notification = json.dumps({
                "type": "subscription_confirmed",
                "from_id": current_user.unique_id,
                "from_phone": decrypt_data(current_user.encrypted_phone)
            })
            message_key = f"ws_message:{req.target_id}"
            await database.redis_client.rpush(message_key, notification)
            await database.redis_client.expire(message_key, 86400)
            if req.target_id in active_connections:
                try:
                    await active_connections[req.target_id]['websocket'].send(notification)
                    logger.info(f"Отправлено сообщение от {current_user.unique_id} к {req.target_id}")
                except Exception as e:
                    logger.warning(f"Не удалось отправить сообщение {req.target_id}: {str(e)}")
            # Очистка Redis после подтверждения
            await database.redis_client.delete(f"secret_sub:{req.target_id}:{current_user.unique_id}")
            await database.redis_client.delete(f"secret_sub:{current_user.unique_id}:{req.target_id}")
            logger.debug(f"Очищены secret_sub ключи для {current_user.unique_id} <-> {req.target_id}")
            logger.info(f"Подписка подтверждена: {current_user.unique_id} <-> {req.target_id}")
            return {"status": "confirmed"}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Ошибка подтверждения подписки для {current_user.unique_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка подтверждения подписки. Попробуйте заново.")

@app.get("/contacts")
async def get_contacts(page: int = 1, per_page: int = 20, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    async with db.begin():
        try:
            cache_key = f"contacts:{current_user.unique_id}:{page}:{per_page}"
            cached = await database.redis_client.get(cache_key)
            if cached:
                logger.debug(f"Контакты найдены в кэше для {current_user.unique_id}")
                return json.loads(cached)
            # Select accepted subscriptions with join to get unique_ids
            stmt_subs = select(User.unique_id).join(Subscription, Subscription.target_id == User.id).filter(
                Subscription.user_id == current_user.id, Subscription.status == 'accepted'
            ).order_by(User.unique_id)
            result_subs = await db.execute(stmt_subs)
            subs_unique_ids = [str(row[0]) for row in result_subs.fetchall()]
            total = len(subs_unique_ids)
            start = (page - 1) * per_page
            end = start + per_page
            paged_ids = subs_unique_ids[start:end]
            contacts = []
            for sub_uid in paged_ids:
                stmt_user = select(User).filter(User.unique_id == sub_uid)
                result_user = await db.execute(stmt_user)
                sub_user = result_user.scalar_one_or_none()
                if sub_user:
                    # Get e2e key
                    stmt_e2e = select(E2EKey).filter(E2EKey.user_id == sub_user.id)
                    result_e2e = await db.execute(stmt_e2e)
                    e2ek = result_e2e.scalar_one_or_none()
                    public_e2e = decrypt_data(e2ek.encrypted_public_key) if e2ek else None
                    contacts.append({
                        "unique_id": sub_user.unique_id,
                        "nickname": decrypt_data(sub_user.encrypted_nickname),
                        "public_e2e_key": public_e2e
                    })
                else:
                    logger.warning(f"Контакт {sub_uid} не найден в БД для {current_user.unique_id}")
            current_user.last_activity = datetime.utcnow()
            await db.merge(current_user)
            response = {"contacts": contacts, "page": page, "per_page": per_page, "total": total, "pages": (total + per_page - 1) // per_page}
            await database.redis_client.set(cache_key, json.dumps(response), ex=300)
            logger.debug(f"Контакты сохранены в кэш для {current_user.unique_id}")
            return response
        except Exception as e:
            logger.error(f"Ошибка получения контактов для {current_user.unique_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка получения контактов. Попробуйте заново.")

@app.get("/profile")
async def get_profile(user_id: Optional[str] = None, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    async with db.begin():
        try:
            csrf_key = f"csrf:{current_user.unique_id}"
            csrf_token = await database.redis_client.get(csrf_key)
            if not csrf_token:
                csrf_token = secrets.token_urlsafe(32)
                await database.redis_client.set(csrf_key, csrf_token, ex=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
                logger.debug(f"Сгенерирован новый CSRF токен для {current_user.unique_id} в /profile")
            response = {"csrf_token": csrf_token}
            if user_id is None:
                dec_phone = decrypt_data(current_user.encrypted_phone)
                dec_name = decrypt_data(current_user.encrypted_name)
                dec_nickname = decrypt_data(current_user.encrypted_nickname)
                dec_username = decrypt_data(current_user.encrypted_username)
                dec_bio = decrypt_data(current_user.encrypted_bio)
                if dec_phone is None or dec_name is None or dec_nickname is None:
                    raise HTTPException(status_code=500, detail="Ошибка расшифровки профиля. Попробуйте заново.")
                # Get e2e key
                stmt_e2e = select(E2EKey).filter(E2EKey.user_id == current_user.id)
                result_e2e = await db.execute(stmt_e2e)
                e2ek = result_e2e.scalar_one_or_none()
                public_e2e = decrypt_data(e2ek.encrypted_public_key) if e2ek else None
                response.update({
                    "unique_id": current_user.unique_id,
                    "phone": dec_phone,
                    "name": dec_name,
                    "nickname": dec_nickname,
                    "username": dec_username,
                    "bio": dec_bio,
                    "public_e2e_key": public_e2e
                })
            else:
                # Check subscription
                stmt_target = select(User.id).filter(User.unique_id == user_id)
                result_target = await db.execute(stmt_target)
                target_pk = result_target.scalar_one_or_none()
                if not target_pk:
                    raise HTTPException(status_code=404, detail="Пользователь не найден.")
                stmt_sub = select(Subscription).filter(Subscription.user_id == current_user.id, Subscription.target_id == target_pk, Subscription.status == 'accepted')
                result_sub = await db.execute(stmt_sub)
                if not result_sub.scalar_one_or_none():
                    raise HTTPException(status_code=403, detail="Не подписаны на этого пользователя.")
                stmt = select(User).filter(User.id == target_pk)
                result = await db.execute(stmt)
                target = result.scalar_one_or_none()
                if not target:
                    raise HTTPException(status_code=404, detail="Пользователь не найден.")
                dec_name = decrypt_data(target.encrypted_name)
                dec_nickname = decrypt_data(target.encrypted_nickname)
                dec_username = decrypt_data(getattr(target, 'encrypted_username', None))
                dec_bio = decrypt_data(getattr(target, 'encrypted_bio', None))
                if dec_name is None or dec_nickname is None:
                    raise HTTPException(status_code=500, detail="Ошибка расшифровки профиля. Попробуйте заново.")
                # Get e2e key
                stmt_e2e = select(E2EKey).filter(E2EKey.user_id == target.id)
                result_e2e = await db.execute(stmt_e2e)
                e2ek = result_e2e.scalar_one_or_none()
                public_e2e = decrypt_data(e2ek.encrypted_public_key) if e2ek else None
                response.update({
                    "unique_id": target.unique_id,
                    "name": dec_name,
                    "nickname": dec_nickname,
                    "username": dec_username,
                    "bio": dec_bio,
                    "public_e2e_key": public_e2e
                })
            # Обновляем last_activity через merge для избежания конфликта сессий
            current_user.last_activity = datetime.utcnow()
            await db.merge(current_user)
            return response
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Ошибка получения профиля для {current_user.unique_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка получения профиля. Попробуйте заново.")

@app.put("/profile")
async def update_profile(req: ProfileUpdateRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    async with db.begin():
        try:
            if req.name:
                current_user.encrypted_name = encrypt_data(req.name)
            if req.nickname:
                current_user.encrypted_nickname = encrypt_data(req.nickname)
            if req.username is not None:
                current_user.encrypted_username = encrypt_data(req.username)
            if req.bio is not None:
                current_user.encrypted_bio = encrypt_data(req.bio)
            if req.password:
                current_user.hashed_password = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
            current_user.last_activity = datetime.utcnow()
            await db.merge(current_user)
            logger.info(f"Профиль обновлен для {current_user.unique_id}")
            return {"status": "updated"}
        except Exception as e:
            logger.error(f"Ошибка обновления профиля для {current_user.unique_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка обновления профиля. Попробуйте заново.")

@app.get("/status")
async def server_status():
    """Server health check and status endpoint"""
    try:
        # Check Redis connection
        redis_ok = False
        try:
            await database.redis_client.ping()
            redis_ok = True
        except Exception as e:
            logger.error(f"Redis health check failed: {str(e)}")
        
        # Check database connection
        db_ok = False
        try:
            async with database.AsyncSessionLocal() as db:
                await db.execute(text("SELECT 1"))
                db_ok = True
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
        
        ws_connections = len(active_connections)
        
        return {
            "status": "ok" if (redis_ok and db_ok) else "degraded",
            "version": SERVER_VERSION,
            "services": {
                "redis": redis_ok,
                "database": db_ok,
                "websocket": True
            },
            "websocket": {
                "connections": ws_connections,
                "port": WS_PORT
            },
            "http_port": HTTP_PORT,
            "ws_port": WS_PORT
        }
    except Exception as e:
        logger.error(f"Status endpoint error: {str(e)}")
        return {
            "status": "error",
            "version": SERVER_VERSION,
            "error": str(e)
        }

@app.get("/statuses")
async def get_statuses(user_ids: str = Query(...), current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    async with db.begin():
        try:
            statuses = {}
            now = datetime.utcnow()
            for uid_str in user_ids.split(','):
                uid_str = uid_str.strip()
                if not uid_str:
                    continue
                uid = int(uid_str)
                # Get target PK
                stmt_target = select(User.id).filter(User.unique_id == uid)
                result_target = await db.execute(stmt_target)
                target_id = result_target.scalar_one_or_none()
                if not target_id:
                    statuses[uid_str] = {"status": "not_found", "typing": False}
                    continue
                # Check subscription
                stmt_sub = select(Subscription).filter(Subscription.user_id == current_user.id, Subscription.target_id == target_id, Subscription.status == 'accepted')
                result_sub = await db.execute(stmt_sub)
                if not result_sub.scalar_one_or_none():
                    statuses[uid_str] = {"status": "not_subscribed", "typing": False}
                    continue
                if uid_str in active_connections:
                    base_status = 'online'
                else:
                    stmt_la = select(User.last_activity).filter(User.unique_id == uid)
                    result_la = await db.execute(stmt_la)
                    la = result_la.scalar_one_or_none()
                    if la and (now - la < timedelta(minutes=5)):
                        base_status = f"was at {la.isoformat()}"
                    elif la and (now - la < timedelta(days=30)):
                        base_status = 'inactive'
                    else:
                        base_status = 'closed'
                typing_to_me = await database.redis_client.exists(f"typing:{uid_str}:{current_user.unique_id}")
                statuses[uid_str] = {"status": base_status, "typing": bool(typing_to_me)}
            current_user.last_activity = now
            await db.merge(current_user)
            return {"statuses": statuses}
        except Exception as e:
            logger.error(f"Ошибка получения статусов для {current_user.unique_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка получения статусов.")

@app.get("/debug/users")
async def debug_users(db: AsyncSession = Depends(get_db)):
    if not DEBUG_MODE:
        logger.warning("Попытка доступа к /debug/users при выключенном DEBUG_MODE")
        raise HTTPException(status_code=403, detail="Debug-режим отключен")
    async with db.begin():
        try:
            stmt = select(User)
            result = await db.execute(stmt)
            users = result.scalars().all()
            user_data = [
                {
                    "id": u.id,
                    "unique_id": u.unique_id,
                    "hashed_phone": u.hashed_phone,
                    "encrypted_phone": u.encrypted_phone,
                    "decrypted_phone": mask_sensitive(decrypt_data(u.encrypted_phone)) if u.encrypted_phone else None,
                    "encrypted_device_id": u.encrypted_device_id,
                    "decrypted_device_id": mask_sensitive(decrypt_data(u.encrypted_device_id)) if u.encrypted_device_id else None,
                    "last_activity": u.last_activity.isoformat() if u.last_activity else None
                } for u in users
            ]
            logger.debug(f"Получены данные пользователей: {len(user_data)} записей")
            return {"users": user_data}
        except Exception as e:
            logger.error(f"Ошибка получения пользователей: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка получения пользователей. Попробуйте заново.")

@app.get("/debug/connections")
async def debug_connections():
    if not DEBUG_MODE:
        logger.warning("Попытка доступа к /debug/connections при выключенном DEBUG_MODE")
        raise HTTPException(status_code=403, detail="Debug-режим отключен")
    try:
        connections = [
            {
                "user_id": user_id,
                "remote_addr": info["remote_addr"],
                "user_agent": mask_sensitive(info["user_agent"]),
                "connected_at": info["connected_at"].isoformat()
            } for user_id, info in active_connections.items()
        ]
        logger.debug(f"Получены активные подключения: {len(connections)}")
        return {"connections": connections}
    except Exception as e:
        logger.error(f"Ошибка получения активных подключений: {str(e)}")
        raise HTTPException(status_code=500, detail="Ошибка получения подключений. Попробуйте заново.")

from app.ws import active_connections, websocket_handler

async def delete_inactive():
    async with database.AsyncSessionLocal() as db_session:
        async with db_session.begin():
            try:
                threshold = datetime.utcnow() - timedelta(days=365)
                stmt = select(User).filter(User.last_activity < threshold)
                result = await db_session.execute(stmt)
                inactive = result.scalars().all()
                for u in inactive:
                    # Удаление по шаблону
                    patterns = [
                        f"ws_message:{u.unique_id}",
                        f"history:{u.unique_id}:*",
                        f"history:*:{u.unique_id}",
                        f"call_pending:{u.unique_id}:*",
                        f"call_pending:*:{u.unique_id}",
                        f"typing:{u.unique_id}:*",
                        f"typing:*:{u.unique_id}",
                        f"push:{u.unique_id}"
                    ]
                    for p in patterns:
                        try:
                            keys = await database.redis_client.keys(p)
                            if keys:
                                await database.redis_client.delete(*keys)
                        except Exception as e:
                            logger.debug(f"Не удалось удалить ключи по шаблону {p}: {str(e)}")
                # Delete related subscriptions and e2e
                stmt_sub = delete(Subscription).where(or_(Subscription.user_id == u.id, Subscription.target_id == u.id))
                await db_session.execute(stmt_sub)
                stmt_e2e = delete(E2EKey).where(E2EKey.user_id == u.id)
                await db_session.execute(stmt_e2e)
                await db_session.delete(u)
                logger.info(f"Удалено {len(inactive)} неактивных пользователей")
            except Exception as e:
                logger.error(f"Ошибка удаления неактивных пользователей: {str(e)}")

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

@app.get("/")
async def root():
    return JSONResponse(content={"detail": f"Я не понимаю вашего запроса Server Version: {SERVER_VERSION}, MVP Server"})

@app.get("/history/{target_id}")
async def get_history(target_id: str, page: int = 1, per_page: int = 50, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if per_page > 100 or per_page < 1:
        raise HTTPException(status_code=400, detail="per_page должен быть от 1 до 100")
    if page < 1:
        raise HTTPException(status_code=400, detail="page должен быть >= 1")
    async with db.begin():
        try:
            # Проверяем подписку
            stmt_target = select(User.id).filter(User.unique_id == target_id)
            result_target = await db.execute(stmt_target)
            target_pk = result_target.scalar_one_or_none()
            if not target_pk:
                raise HTTPException(status_code=404, detail="Пользователь не найден.")
            stmt_sub = select(Subscription).filter(Subscription.user_id == current_user.id, Subscription.target_id == target_pk, Subscription.status == 'accepted')
            result_sub = await db.execute(stmt_sub)
            if not result_sub.scalar_one_or_none():
                raise HTTPException(status_code=403, detail="Не подписаны на этого пользователя.")
            history_key = f"history:{current_user.unique_id}:{target_id}"
            total = await database.redis_client.llen(history_key)
            if total == 0:
                return {"messages": [], "page": page, "per_page": per_page, "total": 0, "pages": 0}
            start = -per_page * page  # Для последних сначала: -per_page*page до -per_page*(page-1)-1
            end = -per_page * (page - 1) - 1
            if start < -total:
                start = -total
            messages = await database.redis_client.lrange(history_key, start, end)
            current_user.last_activity = datetime.utcnow()
            await db.merge(current_user)
            pages = (total + per_page - 1) // per_page
            return {"messages": messages, "page": page, "per_page": per_page, "total": total, "pages": pages}
        except Exception as e:
            logger.error(f"Ошибка получения истории для {current_user.unique_id} и {target_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Ошибка получения истории сообщений. Попробуйте заново.")

async def main():
    global last_cert_mtime, last_key_mtime
    try:
        await setup_db_and_scheduler()
        last_cert_mtime = os.path.getmtime(SSL_CERTFILE)
        last_key_mtime = os.path.getmtime(SSL_KEYFILE)
        
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        ssl_context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256')
        ssl_context.load_cert_chain(certfile=SSL_CERTFILE, keyfile=SSL_KEYFILE)
        logger.info("SSL-сертификаты успешно загружены")
        
        logger.info(f"Запуск WebSocket сервера на порту {WS_PORT}")
        from app.ws import make_ws_server
        ws_server = await make_ws_server(ssl_context, "0.0.0.0", WS_PORT)
        
        http_config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=HTTP_PORT,
            ssl_keyfile=SSL_KEYFILE,
            ssl_certfile=SSL_CERTFILE,
            # Удалено: параметр ssl_version не поддерживается в uvicorn.Config
        )
        http_server = uvicorn.Server(http_config)
        logger.info(f"Запуск HTTP сервера на порту {HTTP_PORT}")
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