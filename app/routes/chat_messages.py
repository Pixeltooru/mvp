from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import json


def build_router(get_db_dep, get_current_user_dep, redis_client):
    router = APIRouter(prefix="/messages", tags=["messages"])

    @router.post("/send")
    async def send_message(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        # payload: { target_id?: string(8), chat_id?: int, data: string(encrypted blob) }
        target_id = (payload or {}).get("target_id")
        chat_id = (payload or {}).get("chat_id")
        data_enc = (payload or {}).get("data")
        if not data_enc or not isinstance(data_enc, str) or len(data_enc) > 2**20:
            raise HTTPException(400, detail="Неверные данные сообщения")
        # DM
        if target_id:
            if not isinstance(target_id, str) or len(target_id) != 8 or not target_id.isdigit():
                raise HTTPException(400, detail="Неверный target_id")
            message_key = f"ws_message:{target_id}"
            offline_delivery = json.dumps({
                'type': 'relay_delivery',
                'message_id': 'srv_' + str(len(data_enc)),
                'from': str(current_user.unique_id),
                'payload': data_enc
            })
            await redis_client.rpush(message_key, offline_delivery)
            await redis_client.expire(message_key, 86400)
            return {"ok": True}
        # Chat/Channel
        if chat_id:
            # push to all members' offline queues; WS delivers to online
            from app.models import ChatMember, User
            async with db.begin():
                rows = await db.execute(select(User.unique_id).join(ChatMember, ChatMember.user_id == User.id).filter(ChatMember.chat_id == chat_id))
                recipients = [str(r[0]) for r in rows.fetchall() if str(r[0]) != str(current_user.unique_id)]
            offline_delivery = json.dumps({'type': 'relay_delivery', 'message_id': 'srv_' + str(len(data_enc)), 'from': str(current_user.unique_id), 'payload': data_enc, 'chat_id': chat_id})
            for r in recipients:
                message_key = f"ws_message:{r}"
                await redis_client.rpush(message_key, offline_delivery)
                await redis_client.expire(message_key, 86400)
            return {"ok": True, "recipients": len(recipients)}
        raise HTTPException(400, detail="Нужно указать target_id или chat_id")

    @router.get("/history/dm/{target_id}")
    async def dm_history(target_id: str, page: int = 1, per_page: int = 50, current_user = Depends(get_current_user_dep)):
        if per_page > 100 or per_page < 1:
            raise HTTPException(status_code=400, detail="per_page должен быть от 1 до 100")
        if page < 1:
            raise HTTPException(status_code=400, detail="page должен быть >= 1")
        history_key = f"history:{current_user.unique_id}:{target_id}"
        total = await redis_client.llen(history_key)
        if total == 0:
            return {"messages": [], "page": page, "per_page": per_page, "total": 0, "pages": 0}
        start = -per_page * page
        end = -per_page * (page - 1) - 1
        if start < -total:
            start = -total
        messages = await redis_client.lrange(history_key, start, end)
        pages = (total + per_page - 1) // per_page
        return {"messages": messages, "page": page, "per_page": per_page, "total": total, "pages": pages}

    @router.get("/history/chat/{chat_id}")
    async def chat_history(chat_id: int, page: int = 1, per_page: int = 50, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        if per_page > 100 or per_page < 1:
            raise HTTPException(status_code=400, detail="per_page должен быть от 1 до 100")
        if page < 1:
            raise HTTPException(status_code=400, detail="page должен быть >= 1")
        # Ensure membership
        from app.models import ChatMember
        async with db.begin():
            mem = await db.execute(select(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == current_user.id))
            if not mem.scalar_one_or_none():
                raise HTTPException(403, detail="Нет доступа к этому чату")
        history_key = f"history:chat:{chat_id}"
        total = await redis_client.llen(history_key)
        if total == 0:
            return {"messages": [], "page": page, "per_page": per_page, "total": 0, "pages": 0}
        start = -per_page * page
        end = -per_page * (page - 1) - 1
        if start < -total:
            start = -total
        messages = await redis_client.lrange(history_key, start, end)
        pages = (total + per_page - 1) // per_page
        return {"messages": messages, "page": page, "per_page": per_page, "total": total, "pages": pages}

    return router
