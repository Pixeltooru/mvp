from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime


def build_router(get_db_dep, get_current_user_dep, Models):
    Chat, ChatMember, User = Models["Chat"], Models["ChatMember"], Models["User"]
    router = APIRouter(prefix="/chats/members", tags=["chat_members"])

    async def require_admin(db: AsyncSession, user_id: int, chat_id: int):
        stmt = select(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == user_id)
        res = await db.execute(stmt)
        m = res.scalar_one_or_none()
        if not m or m.role not in ("owner", "admin"):
            raise HTTPException(403, detail="Недостаточно прав")

    @router.post("/add")
    async def add_member(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        chat_id = (payload or {}).get("chat_id")
        target_uid = (payload or {}).get("user_unique_id")
        if not chat_id or not target_uid:
            raise HTTPException(400, detail="Неверные параметры")
        async with db.begin():
            await require_admin(db, current_user.id, chat_id)
            stmt = select(User).filter(User.unique_id == int(target_uid))
            res = await db.execute(stmt)
            target = res.scalar_one_or_none()
            if not target:
                raise HTTPException(404, detail="Пользователь не найден")
            stmt = select(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == target.id)
            if (await db.execute(stmt)).scalar_one_or_none():
                return {"ok": True}
            db.add(ChatMember(chat_id=chat_id, user_id=target.id, role='member', joined_at=datetime.utcnow()))
        return {"ok": True}

    @router.post("/remove")
    async def remove_member(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        chat_id = (payload or {}).get("chat_id")
        target_uid = (payload or {}).get("user_unique_id")
        if not chat_id or not target_uid:
            raise HTTPException(400, detail="Неверные параметры")
        async with db.begin():
            await require_admin(db, current_user.id, chat_id)
            stmt_user = select(User).filter(User.unique_id == int(target_uid))
            res = await db.execute(stmt_user)
            target = res.scalar_one_or_none()
            if not target:
                return {"ok": True}
            stmt = select(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == target.id)
            member = (await db.execute(stmt)).scalar_one_or_none()
            if member:
                await db.delete(member)
        return {"ok": True}

    @router.post("/role")
    async def set_role(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        chat_id = (payload or {}).get("chat_id")
        target_uid = (payload or {}).get("user_unique_id")
        role = (payload or {}).get("role")
        if not chat_id or not target_uid or role not in ("admin", "member"):
            raise HTTPException(400, detail="Неверные параметры")
        async with db.begin():
            await require_admin(db, current_user.id, chat_id)
            stmt_user = select(User).filter(User.unique_id == int(target_uid))
            res = await db.execute(stmt_user)
            target = res.scalar_one_or_none()
            if not target:
                raise HTTPException(404, detail="Пользователь не найден")
            stmt = select(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == target.id)
            member = (await db.execute(stmt)).scalar_one_or_none()
            if not member:
                raise HTTPException(404, detail="Участник не найден")
            member.role = role
            db.add(member)
        return {"ok": True}

    return router

