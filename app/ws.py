import os
import ssl
import json
import base64
import uuid
import re
import asyncio
import logging
from datetime import datetime
from typing import Dict
from urllib.parse import parse_qs

import websockets
from fastapi import HTTPException
from sqlalchemy import select, or_, delete
from sqlalchemy.ext.asyncio import AsyncSession
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

from app.auth import verify_token
import app.db as database
from app.models import User, Subscription, E2EKey, Chat, ChatMember


logger = logging.getLogger(__name__)

# Config
SERVER_VERSION = os.getenv('SERVER_VERSION', '3.1.1')
WS_RATE_LIMIT_MESSAGES = int(os.getenv('WS_RATE_LIMIT_MESSAGES', '100'))
WS_RATE_LIMIT_PERIOD = int(os.getenv('WS_RATE_LIMIT_PERIOD', '60'))
WS_MAX_CONNECTIONS_PER_IP = int(os.getenv('WS_MAX_CONNECTIONS_PER_IP', '5'))
HISTORY_TTL = int(os.getenv('HISTORY_TTL', str(14 * 24 * 3600)))
ENCRYPTION_KEY_STR = os.getenv('ENCRYPTION_KEY_STR')
if not ENCRYPTION_KEY_STR:
    raise ValueError("ENCRYPTION_KEY_STR не задан в env vars!")
ENCRYPTION_KEY = base64.urlsafe_b64decode(ENCRYPTION_KEY_STR)


def mask_sensitive(data: str) -> str:
    import hashlib
    if not data:
        return 'None'
    return hashlib.sha256(data.encode()).hexdigest()[:8] + '***'


async def check_ws_rate_limit(user_id: str, client_ip: str):
    ws_rate_key = f"ws_rate:{user_id}:{client_ip}"
    count = await database.redis_client.incr(ws_rate_key)
    if count == 1:
        await database.redis_client.expire(ws_rate_key, WS_RATE_LIMIT_PERIOD)
    if count > WS_RATE_LIMIT_MESSAGES:
        logger.warning(f"WebSocket rate limit превышен для {user_id}, IP={client_ip}")
        raise HTTPException(status_code=429, detail="Лимит сообщений превышен. Подождите и попробуйте снова.")


async def check_ws_connections_per_ip(client_ip: str):
    ip_key = f"ws_ip_connections:{client_ip}"
    count = await database.redis_client.incr(ip_key)
    if count == 1:
        await database.redis_client.expire(ip_key, 3600)
    if count > WS_MAX_CONNECTIONS_PER_IP:
        logger.warning(f"Максимум подключений превышен для IP {client_ip}")
        raise HTTPException(status_code=429, detail="Слишком много подключений с этого IP. Подождите и попробуйте снова.")


def decrypt_data(enc_data: str, key: bytes = ENCRYPTION_KEY) -> str:
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


def verify_signature(message: bytes, signature: bytes, public_key_pem: str) -> bool:
    try:
        public_key_obj = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        public_key_obj.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


active_connections: Dict[str, Dict] = {}


async def websocket_handler(websocket, path: str):
    remote_addr = websocket.remote_address if hasattr(websocket, 'remote_address') else ('unknown', 0)
    client_ip = remote_addr[0]
    user_agent = websocket.request_headers.get('user-agent', 'unknown')
    origin = websocket.request_headers.get('origin', '') or 'null'
    
    # Расширенный список allowed origins для Flutter мобильных приложений
    allowed_origins = [
        'https://pixeltoo.ru', 
        'https://mlo.pixeltoo.ru', 
        'file://', 
        'null',
        '',  # Пустой origin от мобильных приложений
    ]
    
    # Для мобильных приложений (Flutter, React Native и т.д.) origin может быть пустым или null
    # Также разрешаем подключения если User-Agent содержит Dart (Flutter)
    is_mobile_app = 'Dart' in user_agent or 'Flutter' in user_agent or origin in ['', 'null']
    
    if not is_mobile_app and origin not in allowed_origins:
        logger.warning(f"❌ [WS] Неверный origin: {origin}, User-Agent: {user_agent}, IP={remote_addr}")
        await websocket.close(code=1008, reason="Неверный origin")
        return
    
    logger.debug(f"✅ [WS] Origin accepted: {origin}, User-Agent: {user_agent}")
    await check_ws_connections_per_ip(client_ip)
    logger.info(f"🔌 [WS] Connection attempt: path={path}, IP={remote_addr[0]}, origin={origin}")
    try:
        # Extract token from Authorization header or query params
        token = websocket.request_headers.get('authorization', '').replace('Bearer ', '')
        if not token:
            query_params = parse_qs(path.lstrip('/?'))
            token = query_params.get('token', [None])[0]
            logger.debug(f"🔑 [WS] Token extracted from query params")
        else:
            logger.debug(f"🔑 [WS] Token extracted from Authorization header")
            
        if not token:
            logger.error(f"❌ [WS] No auth token provided | IP={remote_addr[0]}")
            await websocket.close(code=1008, reason="Отсутствует токен авторизации")
            return
        
        logger.debug(f"🔍 [WS] Verifying token (length: {len(token)})...")
        try:
            payload = await verify_token(token)
            user_id = payload.get('sub')
            logger.info(f"✅ [WS] Token verified successfully | user_id={user_id} | IP={remote_addr[0]}")
        except HTTPException as e:
            logger.error(f"❌ [WS] Token verification failed | code={e.status_code} | detail={e.detail} | IP={remote_addr[0]}")
            await websocket.close(code=1008, reason=f"Ошибка токена [{e.status_code}]: {e.detail}")
            return
        except Exception as e:
            logger.error(f"❌ [WS] Token verification exception | error={str(e)} | IP={remote_addr[0]}")
            await websocket.close(code=1008, reason=f"Ошибка проверки токена: {str(e)}")
            return
        user_id = payload.get("sub")
        if not user_id:
            logger.error(f"WebSocket: Токен не содержит идентификатор пользователя, remote_addr={remote_addr}, user-agent={mask_sensitive(user_agent)}")
            await websocket.close(code=1008, reason="Токен не содержит идентификатор пользователя")
            return
        async with database.AsyncSessionLocal() as db:
            async with db.begin():
                stmt = select(User).filter(User.unique_id == int(user_id))
                result = await db.execute(stmt)
                user = result.scalar_one_or_none()
                if not user:
                    logger.error(f"WebSocket: Пользователь {user_id} не найден, remote_addr={remote_addr}, user-agent={mask_sensitive(user_agent)}")
                    await websocket.close(code=1008, reason="Пользователь не найден")
                    return
                user.last_activity = datetime.utcnow()
                db.add(user)
        active_connections[user_id] = {
            "websocket": websocket,
            "remote_addr": remote_addr,
            "user_agent": user_agent,
            "connected_at": datetime.utcnow()
        }
        
        # Обновляем статус пользователя на онлайн
        await update_user_activity(int(user_id))
        
        logger.info(f"WebSocket подключен: user_id={user_id}, remote_addr={remote_addr}, user-agent={mask_sensitive(user_agent)}")
        message_key = f"ws_message:{user_id}"
        messages = await database.redis_client.lrange(message_key, 0, -1)
        if messages:
            try:
                for msg in messages:
                    await websocket.send(msg)
            except Exception as e:
                logger.error(f"Ошибка отправки сохраненного сообщения для {user_id}: {str(e)}, remote_addr={remote_addr}")
            finally:
                await database.redis_client.delete(message_key)
        try:
            while True:
                try:
                    data_enc = await asyncio.wait_for(websocket.recv(), timeout=60)
                    await check_ws_rate_limit(user_id, client_ip)
                    logger.debug(f"WebSocket: Получены данные от {user_id}: {str(data_enc)[:50]}..., remote_addr={remote_addr}")
                    if not isinstance(data_enc, str):
                        continue
                    if len(data_enc) > 2**20:
                        continue
                    data = None
                    try:
                        data = json.loads(data_enc)
                        if data.get('type') == 'ping':
                            # Собираем статусы контактов
                            async with database.AsyncSessionLocal() as db:
                                async with db.begin():
                                    stmt_subs = select(User.unique_id).join(Subscription, Subscription.target_id == User.id).filter(
                                        Subscription.user_id == user.id, Subscription.status == 'accepted'
                                    )
                                    result_subs = await db.execute(stmt_subs)
                                    subs_unique_ids = [str(row[0]) for row in result_subs.fetchall()]
                            contacts_status = {}
                            for sub_uid in subs_unique_ids:
                                status = 'online' if sub_uid in active_connections else 'offline'
                                typing_from_sub = await database.redis_client.exists(f"typing:{sub_uid}:{user_id}")
                                contacts_status[sub_uid] = {'status': status, 'typing': bool(typing_from_sub)}
                            response = {
                                "type": "pong",
                                "contacts_status": contacts_status,
                                "server_version": SERVER_VERSION,
                                "timestamp": datetime.utcnow().isoformat(),
                            }
                            await websocket.send(json.dumps(response))
                            continue
                    except json.JSONDecodeError:
                        pass
                    if data is None:
                        try:
                            data = json.loads(data_enc)
                        except json.JSONDecodeError:
                            try:
                                decoded_bytes = base64.urlsafe_b64decode(data_enc)
                                data_str = decoded_bytes.decode('utf-8')
                                data = json.loads(data_str)
                            except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
                                continue
                    if 'type' not in data:
                        continue
                    if data['type'] in ['ack_received', 'ack_read']:
                        msg_id = data.get('message_id')
                        other = data.get('other') or data.get('from') or data.get('target')
                        status = 'delivered' if data['type'] == 'ack_received' else 'read'
                        if msg_id and other and other in active_connections:
                            try:
                                await active_connections[other]['websocket'].send(json.dumps({'type': 'msg_status', 'message_id': msg_id, 'status': status, 'from': user_id, 'to': other}))
                            except Exception:
                                pass
                        continue
                    if data['type'] in ['call_connected', 'call_end_state']:
                        target_uid_str = data.get('target')
                        state = 'connected' if data['type'] == 'call_connected' else 'ended'
                        if target_uid_str and target_uid_str in active_connections:
                            try:
                                await active_connections[target_uid_str]['websocket'].send(json.dumps({'type': 'call_state', 'state': state, 'from': user_id, 'to': target_uid_str}))
                            except Exception:
                                pass
                        continue
                    # Routing: direct user or chat/channel
                    target_uid_str = data.get('target')  # 8-значный user id
                    chat_id = data.get('chat_id')       # целевой чат/канал
                    is_chat_message = chat_id is not None
                    if data['type'] not in ['ping', 'get_history']:
                        async with database.AsyncSessionLocal() as db_check:
                            async with db_check.begin():
                                if is_chat_message:
                                    # Проверяем членство и slow-mode
                                    chat = await db_check.get(Chat, int(chat_id))
                                    if not chat:
                                        continue
                                    member = await db_check.execute(select(ChatMember).filter(ChatMember.chat_id == chat.id, ChatMember.user_id == user.id))
                                    m = member.scalar_one_or_none()
                                    if not m:
                                        continue
                                    # slow-mode
                                    if chat.slow_mode_seconds and chat.slow_mode_seconds > 0:
                                        sm_key = f"slow:{chat.id}:{user_id}"
                                        if await database.redis_client.exists(sm_key):
                                            # информируем отправителя
                                            try:
                                                await websocket.send(json.dumps({'type': 'msg_status', 'status': 'rate_limited', 'chat_id': chat.id}))
                                            except Exception:
                                                pass
                                            continue
                                        await database.redis_client.set(sm_key, 1, ex=chat.slow_mode_seconds)
                                else:
                                    # direct: проверяем подписку
                                    if not target_uid_str or not re.match(r'^\d{8}$', target_uid_str):
                                        continue
                                    stmt_target = select(User.id).filter(User.unique_id == int(target_uid_str))
                                    result_target = await db_check.execute(stmt_target)
                                    target_pk = result_target.scalar_one_or_none()
                                    if not target_pk:
                                        continue
                                    stmt = select(Subscription.id).filter(Subscription.user_id == user.id, Subscription.target_id == target_pk, Subscription.status == 'accepted').limit(1)
                                    result = await db_check.execute(stmt)
                                    if not result.first():
                                        continue
                    # Опциональная подпись
                    if 'signature' in data:
                        message_to_verify = json.dumps({k: v for k, v in data.items() if k != 'signature'}).encode()
                        async with database.AsyncSessionLocal() as db_sig:
                            async with db_sig.begin():
                                stmt_e2e = select(E2EKey).filter(E2EKey.user_id == user.id)
                                result_e2e = await db_sig.execute(stmt_e2e)
                                e2ek = result_e2e.scalar_one_or_none()
                        public_pem = decrypt_data(e2ek.encrypted_public_key) if e2ek else None
                        if public_pem and not verify_signature(message_to_verify, base64.b64decode(data['signature']), public_pem):
                            continue
                    if data['type'] == 'get_history':
                        try:
                            history_key = f"history:{user_id}:{target_uid_str}" if target_uid_str else None
                            messages = []
                            if history_key:
                                total = await database.redis_client.llen(history_key)
                                if total:
                                    messages = []
                            await websocket.send(json.dumps({"type": "history", "messages": messages}))
                        except Exception:
                            pass
                        continue
                    if data['type'] == 'typing_start':
                        await database.redis_client.set(f"typing:{user_id}:{target_uid_str}", 1, ex=10)
                    elif data['type'] == 'typing_stop':
                        await database.redis_client.delete(f"typing:{user_id}:{target_uid_str}")
                    # История
                    message_types_for_history = ['ping', 'call_start', 'call_end', 'typing_start', 'typing_stop', 'relay']
                    if data.get('type') not in message_types_for_history or data.get('type') == 'relay':
                        if is_chat_message:
                            history_key_from = f"history:chat:{chat_id}"
                            history_key_to = None
                        else:
                            history_key_from = f"history:{user_id}:{target_uid_str}"
                            history_key_to = f"history:{target_uid_str}:{user_id}"
                        to_store = data.get('payload') if data.get('type') == 'relay' else data_enc
                        await database.redis_client.rpush(history_key_from, to_store)
                        if history_key_to:
                            await database.redis_client.rpush(history_key_to, to_store)
                        await database.redis_client.expire(history_key_from, HISTORY_TTL)
                        if history_key_to:
                            await database.redis_client.expire(history_key_to, HISTORY_TTL)
                    # Доставка
                    forward_payload = data.get('payload') if data.get('type') == 'relay' else data_enc
                    msg_id = uuid.uuid4().hex
                    offline_delivery = json.dumps({'type': 'relay_delivery', 'message_id': msg_id, 'from': user_id, 'payload': forward_payload, 'chat_id': chat_id})
                    if is_chat_message:
                        # отправка всем участникам чата онлайн, остальным — оффлайн очередь на ключи ws_message:userId
                        async with database.AsyncSessionLocal() as dbm:
                            async with dbm.begin():
                                rows = await dbm.execute(select(User.unique_id).join(ChatMember, ChatMember.user_id == User.id).filter(ChatMember.chat_id == int(chat_id)))
                                recipients = [str(r[0]) for r in rows.fetchall() if str(r[0]) != user_id]
                        for r in recipients:
                            message_key = f"ws_message:{r}"
                            await database.redis_client.rpush(message_key, offline_delivery)
                            await database.redis_client.expire(message_key, 86400)
                            if r in active_connections:
                                try:
                                    await active_connections[r]['websocket'].send(json.dumps({'type': 'relay_delivery', 'message_id': msg_id, 'from': user_id, 'payload': forward_payload, 'chat_id': chat_id}))
                                except Exception:
                                    pass
                    else:
                        message_key = f"ws_message:{target_uid_str}"
                        await database.redis_client.rpush(message_key, offline_delivery)
                        await database.redis_client.expire(message_key, 86400)
                        if target_uid_str in active_connections:
                            try:
                                await active_connections[target_uid_str]['websocket'].send(json.dumps({'type': 'relay_delivery', 'message_id': msg_id, 'from': user_id, 'payload': forward_payload}))
                            except Exception:
                                pass
                    try:
                        await websocket.send(json.dumps({'type': 'msg_status', 'message_id': msg_id, 'status': 'queued', 'from': user_id, 'to': target_uid_str}))
                    except Exception:
                        pass
                    if target_uid_str in active_connections:
                        try:
                            await active_connections[target_uid_str]['websocket'].send(json.dumps({'type': 'relay_delivery', 'message_id': msg_id, 'from': user_id, 'payload': forward_payload}))
                            try:
                                await websocket.send(json.dumps({'type': 'msg_status', 'message_id': msg_id, 'status': 'delivered', 'from': user_id, 'to': target_uid_str}))
                            except Exception:
                                pass
                        except Exception:
                            pass
                except asyncio.TimeoutError:
                    continue
                except websockets.exceptions.ConnectionClosed:
                    break
                except ssl.SSLError:
                    break
                except Exception as e:
                    logger.error(f"WebSocket: Ошибка обработки сообщения для {user_id}: {e.__class__.__name__}: {e}")
                    continue
        finally:
                active_connections.pop(user_id, None)
                ip_key = f"ws_ip_connections:{client_ip}"
                try:
                    await database.redis_client.decr(ip_key)
                except Exception:
                    pass
                
                # Устанавливаем пользователя в оффлайн при отключении
                await set_user_offline(int(user_id))
                
                logger.info(f"WebSocket отключен: user_id={user_id}, remote_addr={remote_addr}, user-agent={mask_sensitive(user_agent)}")
    except HTTPException as e:
        await websocket.close(code=1008, reason=e.detail)
    except Exception as e:
        await websocket.close(code=1008, reason="Ошибка сервера. Попробуйте заново.")

async def broadcast_to_contacts(user_id: int, message: dict):
    """Отправить сообщение всем контактам пользователя"""
    try:
        async with database.AsyncSessionLocal() as db:
            # Получаем список контактов (взаимные подписки)
            stmt = select(Subscription).where(
                Subscription.target_id == user_id,
                Subscription.status == 'accepted'
            )
            result = await db.execute(stmt)
            subscriptions = result.scalars().all()
            
            contact_ids = [str(sub.user_id) for sub in subscriptions]
            
            # Отправляем сообщение всем онлайн контактам
            for contact_id in contact_ids:
                if contact_id in active_connections:
                    try:
                        await active_connections[contact_id]['websocket'].send(json.dumps(message))
                    except Exception as e:
                        logger.error(f"Ошибка отправки уведомления контакту {contact_id}: {str(e)}")
                        
    except Exception as e:
        logger.error(f"Ошибка рассылки уведомления контактам: {str(e)}")


async def broadcast_to_chat(chat_id: int, message: dict, exclude_user: int = None):
    """Отправить сообщение всем участникам чата"""
    try:
        async with database.AsyncSessionLocal() as db:
            # Получаем список участников чата
            stmt = select(ChatMember).where(ChatMember.chat_id == chat_id)
            result = await db.execute(stmt)
            members = result.scalars().all()
            
            member_ids = [str(member.user_id) for member in members if member.user_id != exclude_user]
            
            # Отправляем сообщение всем онлайн участникам
            for member_id in member_ids:
                if member_id in active_connections:
                    try:
                        await active_connections[member_id]['websocket'].send(json.dumps(message))
                    except Exception as e:
                        logger.error(f"Ошибка отправки уведомления участнику чата {member_id}: {str(e)}")
                        
    except Exception as e:
        logger.error(f"Ошибка рассылки уведомления в чат {chat_id}: {str(e)}")


async def update_user_activity(user_id: int):
    """Обновить время последней активности пользователя"""
    try:
        async with database.AsyncSessionLocal() as db:
            from app.models import UserStatus
            
            stmt = select(UserStatus).where(UserStatus.user_id == user_id)
            result = await db.execute(stmt)
            status = result.scalar_one_or_none()
            
            if status:
                status.last_seen = datetime.utcnow()
                status.updated_at = datetime.utcnow()
                
                # Если пользователь был оффлайн, меняем статус на онлайн
                if status.status == 'offline':
                    status.status = 'online'
                    # Уведомляем контакты о том, что пользователь появился онлайн
                    await broadcast_to_contacts(user_id, {
                        "type": "status_change",
                        "user_id": user_id,
                        "status": "online",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                
                await db.commit()
            else:
                # Создаем новый статус
                new_status = UserStatus(
                    user_id=user_id,
                    status='online',
                    last_seen=datetime.utcnow()
                )
                db.add(new_status)
                await db.commit()
                
                # Уведомляем контакты
                await broadcast_to_contacts(user_id, {
                    "type": "status_change",
                    "user_id": user_id,
                    "status": "online",
                    "timestamp": datetime.utcnow().isoformat()
                })
                
    except Exception as e:
        logger.error(f"Ошибка обновления активности пользователя {user_id}: {str(e)}")


async def set_user_offline(user_id: int):
    """Установить пользователя в оффлайн при отключении"""
    try:
        async with database.AsyncSessionLocal() as db:
            from app.models import UserStatus
            
            stmt = select(UserStatus).where(UserStatus.user_id == user_id)
            result = await db.execute(stmt)
            status = result.scalar_one_or_none()
            
            if status:
                status.status = 'offline'
                status.last_seen = datetime.utcnow()
                status.updated_at = datetime.utcnow()
                status.is_typing_in_chat = None  # Сбрасываем статус печатания
                status.typing_started_at = None
                
                await db.commit()
                
                # Уведомляем контакты об оффлайн статусе
                await broadcast_to_contacts(user_id, {
                    "type": "status_change",
                    "user_id": user_id,
                    "status": "offline",
                    "timestamp": datetime.utcnow().isoformat()
                })
                
    except Exception as e:
        logger.error(f"Ошибка установки оффлайн статуса для пользователя {user_id}: {str(e)}")


async def make_ws_server(ssl_context: ssl.SSLContext, host: str, port: int):
    # Инициализируем соединения с БД/Redis, если модуль используется автономно
    if database.redis_client is None or database.AsyncSessionLocal is None:
        try:
            await database.init_db_connections()
        except Exception as e:
            logger.error(f"WS: Не удалось инициализировать соединения перед запуском: {str(e)}")
    return await websockets.serve(
        websocket_handler,
        host,
        port,
        ssl=ssl_context,
        max_size=2**20,
        ping_interval=30,
        ping_timeout=20,
    )


