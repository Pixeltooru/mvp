from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from datetime import datetime
from pydantic import BaseModel
from typing import Optional, List


class SessionResponse(BaseModel):
    id: int
    device_type: str
    device_name: Optional[str]
    ip_address: Optional[str]
    created_at: str
    last_activity: str
    is_current: bool


class SessionsListResponse(BaseModel):
    sessions: List[SessionResponse]


def build_router(get_db_dep, get_current_user_dep, UserModel):
    import app.db as database
    from app.models import UserSession
    import logging
    logger = logging.getLogger(__name__)
    
    router = APIRouter(prefix="/sessions", tags=["sessions"])

    @router.get("/", response_model=SessionsListResponse)
    async def list_sessions(
        request: Request,
        current_user = Depends(get_current_user_dep), 
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Получить список всех активных сессий пользователя"""
        async with db.begin():
            # Получаем все активные сессии пользователя
            stmt = select(UserSession).where(
                UserSession.user_id == current_user.id,
                UserSession.is_active == True
            ).order_by(UserSession.last_activity.desc())
            
            result = await db.execute(stmt)
            sessions = result.scalars().all()
            
            # Получаем текущий JTI из токена для определения текущей сессии
            current_jti = getattr(current_user, 'jti', None)
            
            session_list = []
            for session in sessions:
                session_list.append(SessionResponse(
                    id=session.id,
                    device_type=session.device_type,
                    device_name=session.device_name,
                    ip_address=session.ip_address,
                    created_at=session.created_at.isoformat(),
                    last_activity=session.last_activity.isoformat(),
                    is_current=(session.session_token == current_jti)
                ))
            
            return SessionsListResponse(sessions=session_list)

    @router.delete("/{session_id}")
    async def revoke_session(
        session_id: int,
        current_user = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Удалить конкретную сессию"""
        async with db.begin():
            # Находим сессию
            stmt = select(UserSession).where(
                UserSession.id == session_id,
                UserSession.user_id == current_user.id,
                UserSession.is_active == True
            )
            result = await db.execute(stmt)
            session = result.scalar_one_or_none()
            
            if not session:
                raise HTTPException(404, detail="Сессия не найдена")
            
            # Получаем текущий JTI из токена
            current_jti = getattr(current_user, 'jti', None)
            
            # Проверяем, что пользователь не удаляет свою текущую сессию
            if session.session_token == current_jti:
                raise HTTPException(400, detail="Нельзя удалить текущую сессию")
            
            try:
                # Добавляем токен в blacklist
                blacklist_key = f"jwt_blacklist:{session.session_token}"
                await database.redis_client.set(blacklist_key, 1, ex=86400)
                
                # Удаляем из активных токенов
                active_key = f"jwt_active:{current_user.unique_id}:{session.session_token}"
                await database.redis_client.delete(active_key)
                
                # Помечаем сессию как неактивную
                session.is_active = False
                await db.commit()
                
                logger.info(f"Сессия {session_id} отозвана для пользователя {current_user.unique_id}")
                return {"status": "ok", "message": "Сессия успешно удалена"}
                
            except Exception as e:
                logger.error(f"Ошибка отзыва сессии {session_id} для {current_user.unique_id}: {str(e)}")
                raise HTTPException(500, detail="Ошибка удаления сессии")

    @router.post("/revoke_all")
    async def revoke_all_sessions(
        current_user = Depends(get_current_user_dep),
        db: AsyncSession = Depends(get_db_dep)
    ):
        """Удалить все сессии кроме текущей"""
        if not current_user:
            raise HTTPException(401, detail="Unauthorized")
        
        try:
            # Получаем текущий JTI
            current_jti = getattr(current_user, 'jti', None)
            
            async with db.begin():
                # Получаем все активные сессии кроме текущей
                stmt = select(UserSession).where(
                    UserSession.user_id == current_user.id,
                    UserSession.is_active == True,
                    UserSession.session_token != current_jti
                )
                result = await db.execute(stmt)
                sessions = result.scalars().all()
                
                revoked_count = 0
                for session in sessions:
                    # Добавляем в blacklist
                    blacklist_key = f"jwt_blacklist:{session.session_token}"
                    await database.redis_client.set(blacklist_key, 1, ex=86400)
                    
                    # Удаляем из активных
                    active_key = f"jwt_active:{current_user.unique_id}:{session.session_token}"
                    await database.redis_client.delete(active_key)
                    
                    # Помечаем как неактивную
                    session.is_active = False
                    revoked_count += 1
                
                await db.commit()
            
            logger.info(f"Отозваны все сессии для пользователя {current_user.unique_id}: {revoked_count} сессий")
            return {"status": "ok", "revoked_count": revoked_count}
            
        except Exception as e:
            logger.error(f"Ошибка отзыва всех сессий для {current_user.unique_id}: {str(e)}")
            raise HTTPException(500, detail="Ошибка отзыва сессий")

    return router


