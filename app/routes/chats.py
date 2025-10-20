from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
from typing import Optional
import secrets


def build_router(get_db_dep, get_current_user_dep, BaseModelRefs):
    Chat, ChatMember, User = BaseModelRefs["Chat"], BaseModelRefs["ChatMember"], BaseModelRefs["User"]
    router = APIRouter(prefix="/chats", tags=["chats"])

    @router.post("/create")
    async def create_chat(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        name = (payload or {}).get("name")
        kind = (payload or {}).get("type") or "chat"  # chat | channel
        if not name or len(name) < 2:
            raise HTTPException(400, detail="Название слишком короткое")
        if kind not in ("chat", "channel"):
            raise HTTPException(400, detail="Неверный тип")
        async with db.begin():
            chat = Chat(name=name, type=kind, created_at=datetime.utcnow(), owner_id=current_user.id)
            db.add(chat)
            await db.flush()
            member = ChatMember(chat_id=chat.id, user_id=current_user.id, role='owner', joined_at=datetime.utcnow())
            db.add(member)
        return {"ok": True, "chat_id": chat.id, "type": kind}

    @router.post("/set_public")
    async def set_public(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        chat_id = (payload or {}).get("chat_id")
        is_public = bool((payload or {}).get("is_public"))
        async with db.begin():
            chat = await db.get(Chat, chat_id)
            if not chat:
                raise HTTPException(404, detail="Чат не найден")
            # Только владелец
            member = await db.execute(select(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == current_user.id))
            m = member.scalar_one_or_none()
            if not m or m.role != 'owner':
                raise HTTPException(403, detail="Только владелец может менять публичность")
            chat.is_public = is_public
            if is_public and not chat.invite_code:
                chat.invite_code = secrets.token_urlsafe(10)
            db.add(chat)
        return {"ok": True, "invite": chat.invite_code if chat.is_public else None}

    @router.post("/set_slow_mode")
    async def set_slow_mode(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        chat_id = (payload or {}).get("chat_id")
        seconds = int((payload or {}).get("seconds") or 0)
        if seconds < 0 or seconds > 86400:
            raise HTTPException(400, detail="Неверный интервал slow mode")
        async with db.begin():
            chat = await db.get(Chat, chat_id)
            if not chat:
                raise HTTPException(404, detail="Чат не найден")
            member = await db.execute(select(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == current_user.id))
            m = member.scalar_one_or_none()
            if not m or m.role not in ('owner', 'admin'):
                raise HTTPException(403, detail="Требуются права модератора")
            chat.slow_mode_seconds = seconds
            db.add(chat)
        return {"ok": True, "slow_mode": seconds}

    @router.get("/by_invite/{code}")
    async def get_by_invite(code: str, db: AsyncSession = Depends(get_db_dep)):
        async with db.begin():
            stmt = select(Chat).filter(Chat.invite_code == code, Chat.is_public == True)
            res = await db.execute(stmt)
            chat = res.scalar_one_or_none()
            if not chat:
                raise HTTPException(404, detail="Канал не найден")
            return {"chat_id": chat.id, "name": chat.name, "type": chat.type}

    @router.get("/list")
    async def list_chats(page: int = 1, per_page: int = 20, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        """Get list of user's chats and channels"""
        async with db.begin():
            from sqlalchemy import desc
            # Get chats where user is a member
            stmt = (
                select(Chat)
                .join(ChatMember, ChatMember.chat_id == Chat.id)
                .filter(ChatMember.user_id == current_user.id)
                .order_by(desc(Chat.created_at))
                .offset((page - 1) * per_page)
                .limit(per_page)
            )
            result = await db.execute(stmt)
            chats = result.scalars().all()
            
            # Count total
            from sqlalchemy import func
            count_stmt = (
                select(func.count(Chat.id))
                .join(ChatMember, ChatMember.chat_id == Chat.id)
                .filter(ChatMember.user_id == current_user.id)
            )
            count_result = await db.execute(count_stmt)
            total = count_result.scalar() or 0
            
            chats_list = []
            for chat in chats:
                # Get member role
                member_stmt = select(ChatMember).filter(
                    ChatMember.chat_id == chat.id,
                    ChatMember.user_id == current_user.id
                )
                member_res = await db.execute(member_stmt)
                member = member_res.scalar_one_or_none()
                
                chats_list.append({
                    "id": chat.id,
                    "name": chat.name,
                    "type": chat.type,
                    "created_at": chat.created_at.isoformat() if chat.created_at else None,
                    "owner_id": chat.owner_id,
                    "is_public": chat.is_public or False,
                    "invite_code": chat.invite_code if chat.is_public else None,
                    "slow_mode_seconds": chat.slow_mode_seconds or 0,
                    "role": member.role if member else "member",
                })
            
            return {
                "chats": chats_list,
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page if per_page > 0 else 0
            }

    return router

