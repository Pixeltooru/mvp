#!/usr/bin/env python3
"""
Скрипт миграции для шифрования всех незащищенных данных в MySQL и Redis
Стратегия: "Сервер ничего не знает о вас!"

Использование:
    python migrate_encrypt_data.py --dry-run  # Показать что будет зашифровано
    python migrate_encrypt_data.py            # Выполнить миграцию
"""
import os
import sys
import asyncio
import argparse
import logging
from datetime import datetime
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv(dotenv_path='.env')

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('migration_encrypt.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Импорты после загрузки env
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
import app.db as database
from app.models import (
    User, Chat, ChatMember, UserSession, UserStatus, MessageReadStatus
)
from app.encryption import (
    encrypt_data, encrypt_datetime, encrypt_json
)


async def migrate_users(session: AsyncSession, dry_run: bool = False):
    """Мигрирует данные пользователей"""
    logger.info("=" * 60)
    logger.info("Миграция таблицы users")
    logger.info("=" * 60)
    
    stmt = select(User)
    result = await session.execute(stmt)
    users = result.scalars().all()
    
    migrated_count = 0
    for user in users:
        changes = []
        
        # avatar_mime -> encrypted_avatar_mime
        if user.avatar_mime and not user.encrypted_avatar_mime:
            if not dry_run:
                user.encrypted_avatar_mime = encrypt_data(user.avatar_mime)
            changes.append(f"avatar_mime: {user.avatar_mime[:20]}...")
        
        # e2e_key_updated -> encrypted_e2e_key_updated
        if user.e2e_key_updated and not user.encrypted_e2e_key_updated:
            if not dry_run:
                user.encrypted_e2e_key_updated = encrypt_datetime(user.e2e_key_updated)
            changes.append(f"e2e_key_updated: {user.e2e_key_updated}")
        
        # last_activity -> encrypted_last_activity
        if user.last_activity and not user.encrypted_last_activity:
            if not dry_run:
                user.encrypted_last_activity = encrypt_datetime(user.last_activity)
            changes.append(f"last_activity: {user.last_activity}")
        
        if changes:
            migrated_count += 1
            logger.info(f"User {user.unique_id}: {', '.join(changes)}")
            if not dry_run:
                session.add(user)
    
    if not dry_run:
        await session.commit()
    
    logger.info(f"Мигрировано пользователей: {migrated_count}/{len(users)}")
    return migrated_count


async def migrate_chats(session: AsyncSession, dry_run: bool = False):
    """Мигрирует данные чатов"""
    logger.info("=" * 60)
    logger.info("Миграция таблицы chats")
    logger.info("=" * 60)
    
    stmt = select(Chat)
    result = await session.execute(stmt)
    chats = result.scalars().all()
    
    migrated_count = 0
    for chat in chats:
        changes = []
        
        # name -> encrypted_name
        if chat.name and not chat.encrypted_name:
            if not dry_run:
                chat.encrypted_name = encrypt_data(chat.name)
            changes.append(f"name: {chat.name}")
        
        # created_at -> encrypted_created_at
        if chat.created_at and not chat.encrypted_created_at:
            if not dry_run:
                chat.encrypted_created_at = encrypt_datetime(chat.created_at)
            changes.append(f"created_at: {chat.created_at}")
        
        # invite_code -> encrypted_invite_code
        if chat.invite_code and not chat.encrypted_invite_code:
            if not dry_run:
                chat.encrypted_invite_code = encrypt_data(chat.invite_code)
            changes.append(f"invite_code: {chat.invite_code}")
        
        if changes:
            migrated_count += 1
            logger.info(f"Chat {chat.id}: {', '.join(changes)}")
            if not dry_run:
                session.add(chat)
    
    if not dry_run:
        await session.commit()
    
    logger.info(f"Мигрировано чатов: {migrated_count}/{len(chats)}")
    return migrated_count


async def migrate_chat_members(session: AsyncSession, dry_run: bool = False):
    """Мигрирует данные участников чатов"""
    logger.info("=" * 60)
    logger.info("Миграция таблицы chat_members")
    logger.info("=" * 60)
    
    stmt = select(ChatMember)
    result = await session.execute(stmt)
    members = result.scalars().all()
    
    migrated_count = 0
    for member in members:
        changes = []
        
        # joined_at -> encrypted_joined_at
        if member.joined_at and not member.encrypted_joined_at:
            if not dry_run:
                member.encrypted_joined_at = encrypt_datetime(member.joined_at)
            changes.append(f"joined_at: {member.joined_at}")
        
        if changes:
            migrated_count += 1
            logger.info(f"ChatMember {member.id}: {', '.join(changes)}")
            if not dry_run:
                session.add(member)
    
    if not dry_run:
        await session.commit()
    
    logger.info(f"Мигрировано участников чатов: {migrated_count}/{len(members)}")
    return migrated_count


async def migrate_user_sessions(session: AsyncSession, dry_run: bool = False):
    """Мигрирует данные сессий пользователей"""
    logger.info("=" * 60)
    logger.info("Миграция таблицы user_sessions")
    logger.info("=" * 60)
    
    stmt = select(UserSession)
    result = await session.execute(stmt)
    sessions = result.scalars().all()
    
    migrated_count = 0
    for sess in sessions:
        changes = []
        
        # device_type -> encrypted_device_type
        if sess.device_type and not sess.encrypted_device_type:
            if not dry_run:
                sess.encrypted_device_type = encrypt_data(sess.device_type)
            changes.append(f"device_type: {sess.device_type}")
        
        # device_name -> encrypted_device_name
        if sess.device_name and not sess.encrypted_device_name:
            if not dry_run:
                sess.encrypted_device_name = encrypt_data(sess.device_name)
            changes.append(f"device_name: {sess.device_name[:30]}...")
        
        # ip_address -> encrypted_ip_address
        if sess.ip_address and not sess.encrypted_ip_address:
            if not dry_run:
                sess.encrypted_ip_address = encrypt_data(sess.ip_address)
            changes.append(f"ip_address: {sess.ip_address}")
        
        # user_agent -> encrypted_user_agent
        if sess.user_agent and not sess.encrypted_user_agent:
            if not dry_run:
                sess.encrypted_user_agent = encrypt_data(sess.user_agent)
            changes.append(f"user_agent: {sess.user_agent[:30]}...")
        
        # created_at -> encrypted_created_at
        if sess.created_at and not sess.encrypted_created_at:
            if not dry_run:
                sess.encrypted_created_at = encrypt_datetime(sess.created_at)
            changes.append(f"created_at: {sess.created_at}")
        
        # last_activity -> encrypted_last_activity
        if sess.last_activity and not sess.encrypted_last_activity:
            if not dry_run:
                sess.encrypted_last_activity = encrypt_datetime(sess.last_activity)
            changes.append(f"last_activity: {sess.last_activity}")
        
        if changes:
            migrated_count += 1
            logger.info(f"UserSession {sess.id}: {', '.join(changes)}")
            if not dry_run:
                session.add(sess)
    
    if not dry_run:
        await session.commit()
    
    logger.info(f"Мигрировано сессий: {migrated_count}/{len(sessions)}")
    return migrated_count


async def migrate_user_statuses(session: AsyncSession, dry_run: bool = False):
    """Мигрирует данные статусов пользователей"""
    logger.info("=" * 60)
    logger.info("Миграция таблицы user_statuses")
    logger.info("=" * 60)
    
    stmt = select(UserStatus)
    result = await session.execute(stmt)
    statuses = result.scalars().all()
    
    migrated_count = 0
    for status in statuses:
        changes = []
        
        # last_seen -> encrypted_last_seen
        if status.last_seen and not status.encrypted_last_seen:
            if not dry_run:
                status.encrypted_last_seen = encrypt_datetime(status.last_seen)
            changes.append(f"last_seen: {status.last_seen}")
        
        # updated_at -> encrypted_updated_at
        if status.updated_at and not status.encrypted_updated_at:
            if not dry_run:
                status.encrypted_updated_at = encrypt_datetime(status.updated_at)
            changes.append(f"updated_at: {status.updated_at}")
        
        if changes:
            migrated_count += 1
            logger.info(f"UserStatus {status.user_id}: {', '.join(changes)}")
            if not dry_run:
                session.add(status)
    
    if not dry_run:
        await session.commit()
    
    logger.info(f"Мигрировано статусов: {migrated_count}/{len(statuses)}")
    return migrated_count


async def migrate_message_read_statuses(session: AsyncSession, dry_run: bool = False):
    """Мигрирует данные статусов прочтения сообщений"""
    logger.info("=" * 60)
    logger.info("Миграция таблицы message_read_statuses")
    logger.info("=" * 60)
    
    stmt = select(MessageReadStatus)
    result = await session.execute(stmt)
    statuses = result.scalars().all()
    
    migrated_count = 0
    for status in statuses:
        changes = []
        
        # last_read_message_id -> encrypted_last_read_message_id
        if status.last_read_message_id and not status.encrypted_last_read_message_id:
            if not dry_run:
                status.encrypted_last_read_message_id = encrypt_data(status.last_read_message_id)
            changes.append(f"last_read_message_id: {status.last_read_message_id}")
        
        # read_at -> encrypted_read_at
        if status.read_at and not status.encrypted_read_at:
            if not dry_run:
                status.encrypted_read_at = encrypt_datetime(status.read_at)
            changes.append(f"read_at: {status.read_at}")
        
        # updated_at -> encrypted_updated_at
        if status.updated_at and not status.encrypted_updated_at:
            if not dry_run:
                status.encrypted_updated_at = encrypt_datetime(status.updated_at)
            changes.append(f"updated_at: {status.updated_at}")
        
        if changes:
            migrated_count += 1
            logger.info(f"MessageReadStatus {status.id}: {', '.join(changes)}")
            if not dry_run:
                session.add(status)
    
    if not dry_run:
        await session.commit()
    
    logger.info(f"Мигрировано статусов прочтения: {migrated_count}/{len(statuses)}")
    return migrated_count


async def migrate_redis_data(dry_run: bool = False):
    """Мигрирует данные в Redis"""
    logger.info("=" * 60)
    logger.info("Миграция данных Redis")
    logger.info("=" * 60)
    
    migrated_count = 0
    
    # Шифруем CSRF токены
    csrf_keys = await database.redis_client.keys("csrf:*")
    for key in csrf_keys:
        value = await database.redis_client.get(key)
        if value and not value.startswith("gAAAAA"):  # Проверяем, не зашифровано ли уже
            encrypted = encrypt_data(value)
            if encrypted and not dry_run:
                ttl = await database.redis_client.ttl(key)
                await database.redis_client.set(key, encrypted, ex=ttl if ttl > 0 else None)
            migrated_count += 1
            logger.info(f"CSRF token: {key}")
    
    # Шифруем device токены
    device_keys = await database.redis_client.keys("device:*")
    for key in device_keys:
        value = await database.redis_client.get(key)
        if value and not value.startswith("gAAAAA"):
            encrypted = encrypt_data(value)
            if encrypted and not dry_run:
                ttl = await database.redis_client.ttl(key)
                await database.redis_client.set(key, encrypted, ex=ttl if ttl > 0 else None)
            migrated_count += 1
            logger.info(f"Device token: {key}")
    
    # Шифруем push подписки
    push_keys = await database.redis_client.keys("push:*")
    for key in push_keys:
        value = await database.redis_client.get(key)
        if value and value.startswith("{"):  # JSON, не зашифровано
            encrypted = encrypt_data(value)
            if encrypted and not dry_run:
                ttl = await database.redis_client.ttl(key)
                await database.redis_client.set(key, encrypted, ex=ttl if ttl > 0 else None)
            migrated_count += 1
            logger.info(f"Push subscription: {key}")
    
    logger.info(f"Мигрировано ключей Redis: {migrated_count}")
    return migrated_count


async def main():
    parser = argparse.ArgumentParser(description='Миграция шифрования данных')
    parser.add_argument('--dry-run', action='store_true', help='Показать что будет зашифровано без изменений')
    args = parser.parse_args()
    
    if args.dry_run:
        logger.info("=" * 60)
        logger.info("РЕЖИМ DRY-RUN: Изменения НЕ будут сохранены")
        logger.info("=" * 60)
    else:
        logger.info("=" * 60)
        logger.info("ВНИМАНИЕ: Начинается миграция данных!")
        logger.info("Убедитесь, что у вас есть резервная копия БД")
        logger.info("=" * 60)
        response = input("Продолжить? (yes/no): ")
        if response.lower() != 'yes':
            logger.info("Миграция отменена")
            return
    
    try:
        # Инициализация БД и Redis
        await database.init_db_connections()
        logger.info("Подключение к БД и Redis установлено")
        
        # Миграция MySQL
        async with database.AsyncSessionLocal() as session:
            total_mysql = 0
            total_mysql += await migrate_users(session, args.dry_run)
            total_mysql += await migrate_chats(session, args.dry_run)
            total_mysql += await migrate_chat_members(session, args.dry_run)
            total_mysql += await migrate_user_sessions(session, args.dry_run)
            total_mysql += await migrate_user_statuses(session, args.dry_run)
            total_mysql += await migrate_message_read_statuses(session, args.dry_run)
        
        # Миграция Redis
        total_redis = await migrate_redis_data(args.dry_run)
        
        logger.info("=" * 60)
        logger.info("ИТОГИ МИГРАЦИИ")
        logger.info("=" * 60)
        logger.info(f"Всего записей MySQL: {total_mysql}")
        logger.info(f"Всего ключей Redis: {total_redis}")
        logger.info(f"Общий итог: {total_mysql + total_redis}")
        
        if args.dry_run:
            logger.info("Это был DRY-RUN. Запустите без --dry-run для применения изменений")
        else:
            logger.info("Миграция успешно завершена!")
            logger.info("Все чувствительные данные теперь зашифрованы")
            logger.info("Стратегия 'Сервер ничего не знает о вас!' реализована")
        
    except Exception as e:
        logger.error(f"Ошибка миграции: {str(e)}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
