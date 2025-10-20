from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
import secrets


def build_router(get_db_dep, get_current_user_dep, Models, redis_client):
    Chat, ChatMember, User = Models["Chat"], Models["ChatMember"], Models["User"]
    router = APIRouter(prefix="/invites", tags=["invites"])

    async def require_admin(db: AsyncSession, user_id: int, chat_id: int):
        stmt = select(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == user_id)
        res = await db.execute(stmt)
        m = res.scalar_one_or_none()
        if not m or m.role not in ("owner", "admin"):
            raise HTTPException(403, detail="Недостаточно прав")

    @router.post("/create")
    async def create_invite(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        chat_id = (payload or {}).get("chat_id")
        ttl_minutes = int((payload or {}).get("ttl_minutes") or 60)
        if not chat_id:
            raise HTTPException(400, detail="Неверные параметры")
        await require_admin(db, current_user.id, chat_id)
        code = secrets.token_urlsafe(10)
        key = f"invite:{code}"
        await redis_client.set(key, str(chat_id), ex=ttl_minutes*60)
        return {"ok": True, "code": code, "expires_in": ttl_minutes*60}

    @router.post("/join")
    async def join_by_invite(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        code = (payload or {}).get("code")
        if not code:
            raise HTTPException(400, detail="Неверный код")
        key = f"invite:{code}"
        chat_id = await redis_client.get(key)
        if not chat_id:
            raise HTTPException(404, detail="Код недействителен")
        async with db.begin():
            stmt = select(ChatMember).filter(ChatMember.chat_id == int(chat_id), ChatMember.user_id == current_user.id)
            if (await db.execute(stmt)).scalar_one_or_none():
                return {"ok": True}
            db.add(ChatMember(chat_id=int(chat_id), user_id=current_user.id, role='member', joined_at=datetime.utcnow()))
        return {"ok": True}

    return router

