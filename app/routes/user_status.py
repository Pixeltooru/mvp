from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional, List, Dict


class UserStatusResponse(BaseModel):
    user_id: int
    status: str  # online, offline, away
    last_seen: str
    is_typing_in_chat: Optional[int]


class ContactStatusResponse(BaseModel):
    user_id: int
    status: str
    last_seen: str
    is_typing_in_chat: Optional[int]


class ContactsStatusResponse(BaseModel):
    contacts: List[ContactStatusResponse]


class TypingStatusRequest(BaseModel):
    chat_id: Optional[int] = None  # None для остановки печатания


class MessageReadRequest(BaseModel):
    chat_id: int
    message_id: str


def build_router(get_db_dep, get_current_user_dep, UserModel):
    import app.db as database
    from app.models import UserStatus, MessageReadStatus, Subscription
    import logging
    logger = logging.getLogger(__name__)
    
    router = APIRouter(prefix="/status", tags=["user_status"])

    @router.get("/me", response_model=UserStatusResponse)
    async def get_my_status(
        current_user = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Получить свой статус"""
        async with db.begin():
            stmt = select(UserStatus).where(UserStatus.user_id == current_user.id)
            result = await db.execute(stmt)
            status = result.scalar_one_or_none()
            
            if not status:
                # Создаем статус если его нет
                status = UserStatus(
                    user_id=current_user.id,
                    status='online',
                    last_seen=datetime.utcnow()
                )
                db.add(status)
                await db.commit()
            
            return UserStatusResponse(
                user_id=status.user_id,
                status=status.status,
                last_seen=status.last_seen.isoformat(),
                is_typing_in_chat=status.is_typing_in_chat
            )

    @router.post("/typing")
    async def set_typing_status(
        typing_request: TypingStatusRequest,
        current_user = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Установить статус печатания в чате"""
        async with db.begin():
            # Получаем или создаем статус пользователя
            stmt = select(UserStatus).where(UserStatus.user_id == current_user.id)
            result = await db.execute(stmt)
            status = result.scalar_one_or_none()
            
            if not status:
                status = UserStatus(
                    user_id=current_user.id,
                    status='online',
                    last_seen=datetime.utcnow()
                )
                db.add(status)
            
            # Обновляем статус печатания
            if typing_request.chat_id:
                status.is_typing_in_chat = typing_request.chat_id
                status.typing_started_at = datetime.utcnow()
            else:
                status.is_typing_in_chat = None
                status.typing_started_at = None
            
            status.updated_at = datetime.utcnow()
            await db.commit()
            
            # Отправляем уведомление через WebSocket
            await _broadcast_typing_status(current_user.id, typing_request.chat_id)
            
            return {"status": "ok"}

    @router.post("/read")
    async def mark_messages_read(
        read_request: MessageReadRequest,
        current_user = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Отметить сообщения как прочитанные"""
        async with db.begin():
            # Проверяем существующую запись
            stmt = select(MessageReadStatus).where(
                MessageReadStatus.user_id == current_user.id,
                MessageReadStatus.chat_id == read_request.chat_id
            )
            result = await db.execute(stmt)
            read_status = result.scalar_one_or_none()
            
            if read_status:
                # Обновляем существующую запись
                read_status.last_read_message_id = read_request.message_id
                read_status.read_at = datetime.utcnow()
                read_status.updated_at = datetime.utcnow()
            else:
                # Создаем новую запись
                read_status = MessageReadStatus(
                    user_id=current_user.id,
                    chat_id=read_request.chat_id,
                    last_read_message_id=read_request.message_id,
                    read_at=datetime.utcnow()
                )
                db.add(read_status)
            
            await db.commit()
            
            # Отправляем уведомление через WebSocket
            await _broadcast_read_status(current_user.id, read_request.chat_id, read_request.message_id)
            
            return {"status": "ok"}

    @router.get("/contacts", response_model=ContactsStatusResponse)
    async def get_contacts_status(
        current_user = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Получить статусы всех контактов"""
        async with db.begin():
            # Получаем список контактов (подписки)
            stmt = select(Subscription).where(
                Subscription.user_id == current_user.id,
                Subscription.status == 'accepted'
            )
            result = await db.execute(stmt)
            subscriptions = result.scalars().all()
            
            contact_ids = [sub.target_id for sub in subscriptions]
            
            if not contact_ids:
                return ContactsStatusResponse(contacts=[])
            
            # Получаем статусы контактов
            stmt = select(UserStatus).where(UserStatus.user_id.in_(contact_ids))
            result = await db.execute(stmt)
            statuses = result.scalars().all()
            
            # Создаем словарь статусов
            status_dict = {status.user_id: status for status in statuses}
            
            contacts = []
            for contact_id in contact_ids:
                status = status_dict.get(contact_id)
                if status:
                    contacts.append(ContactStatusResponse(
                        user_id=contact_id,
                        status=status.status,
                        last_seen=status.last_seen.isoformat(),
                        is_typing_in_chat=status.is_typing_in_chat
                    ))
                else:
                    # Контакт без статуса считается offline
                    contacts.append(ContactStatusResponse(
                        user_id=contact_id,
                        status='offline',
                        last_seen=datetime.utcnow().isoformat(),
                        is_typing_in_chat=None
                    ))
            
            return ContactsStatusResponse(contacts=contacts)

    @router.post("/online")
    async def set_online_status(
        current_user = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Установить статус онлайн"""
        async with db.begin():
            stmt = select(UserStatus).where(UserStatus.user_id == current_user.id)
            result = await db.execute(stmt)
            status = result.scalar_one_or_none()
            
            if not status:
                status = UserStatus(
                    user_id=current_user.id,
                    status='online',
                    last_seen=datetime.utcnow()
                )
                db.add(status)
            else:
                old_status = status.status
                status.status = 'online'
                status.last_seen = datetime.utcnow()
                status.updated_at = datetime.utcnow()
                
                # Если статус изменился, отправляем уведомление
                if old_status != 'online':
                    await _broadcast_status_change(current_user.id, 'online')
            
            await db.commit()
            return {"status": "ok"}

    @router.post("/offline")
    async def set_offline_status(
        current_user = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Установить статус оффлайн"""
        async with db.begin():
            stmt = select(UserStatus).where(UserStatus.user_id == current_user.id)
            result = await db.execute(stmt)
            status = result.scalar_one_or_none()
            
            if not status:
                status = UserStatus(
                    user_id=current_user.id,
                    status='offline',
                    last_seen=datetime.utcnow()
                )
                db.add(status)
            else:
                status.status = 'offline'
                status.last_seen = datetime.utcnow()
                status.updated_at = datetime.utcnow()
                status.is_typing_in_chat = None  # Сбрасываем статус печатания
                status.typing_started_at = None
                
                await _broadcast_status_change(current_user.id, 'offline')
            
            await db.commit()
            return {"status": "ok"}

    async def _broadcast_status_change(user_id: int, new_status: str):
        """Отправить уведомление об изменении статуса контактам"""
        try:
            # Импортируем здесь чтобы избежать циклических импортов
            from app.ws import broadcast_to_contacts
            
            message = {
                "type": "status_change",
                "user_id": user_id,
                "status": new_status,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await broadcast_to_contacts(user_id, message)
        except Exception as e:
            logger.error(f"Ошибка отправки уведомления о статусе: {str(e)}")

    async def _broadcast_typing_status(user_id: int, chat_id: Optional[int]):
        """Отправить уведомление о статусе печатания"""
        try:
            from app.ws import broadcast_to_chat
            
            if chat_id:
                message = {
                    "type": "typing_start",
                    "user_id": user_id,
                    "chat_id": chat_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
                await broadcast_to_chat(chat_id, message, exclude_user=user_id)
            else:
                # Уведомление об остановке печатания
                message = {
                    "type": "typing_stop",
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
                # Отправляем во все чаты где пользователь мог печатать
                await broadcast_to_contacts(user_id, message)
        except Exception as e:
            logger.error(f"Ошибка отправки уведомления о печатании: {str(e)}")

    async def _broadcast_read_status(user_id: int, chat_id: int, message_id: str):
        """Отправить уведомление о прочтении сообщений"""
        try:
            from app.ws import broadcast_to_chat
            
            message = {
                "type": "messages_read",
                "user_id": user_id,
                "chat_id": chat_id,
                "last_read_message_id": message_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await broadcast_to_chat(chat_id, message, exclude_user=user_id)
        except Exception as e:
            logger.error(f"Ошибка отправки уведомления о прочтении: {str(e)}")

    return router
