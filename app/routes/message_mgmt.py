from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
import json


def build_router(get_db_dep, get_current_user_dep, redis_client):
    router = APIRouter(prefix="/messages", tags=["messages_mgmt"])

    @router.post("/edit")
    async def edit_message(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        # payload: { target_id, message_id, new_data }
        # В простом MVP редактирование — новая оффлайн запись с типом edit
        target_id = (payload or {}).get("target_id")
        message_id = (payload or {}).get("message_id")
        new_data = (payload or {}).get("new_data")
        if not target_id or not message_id or not new_data:
            raise HTTPException(400, detail="Неверные параметры")
        key = f"ws_message:{target_id}"
        patch = json.dumps({'type': 'edit', 'message_id': message_id, 'from': str(current_user.unique_id), 'payload': new_data})
        await redis_client.rpush(key, patch)
        await redis_client.expire(key, 86400)
        return {"ok": True}

    @router.post("/delete")
    async def delete_message(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        target_id = (payload or {}).get("target_id")
        message_id = (payload or {}).get("message_id")
        if not target_id or not message_id:
            raise HTTPException(400, detail="Неверные параметры")
        key = f"ws_message:{target_id}"
        tomb = json.dumps({'type': 'delete', 'message_id': message_id, 'from': str(current_user.unique_id)})
        await redis_client.rpush(key, tomb)
        await redis_client.expire(key, 86400)
        return {"ok": True}

    @router.post("/pin")
    async def pin_message(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        target_id = (payload or {}).get("target_id")
        message_id = (payload or {}).get("message_id")
        if not target_id or not message_id:
            raise HTTPException(400, detail="Неверные параметры")
        key = f"ws_message:{target_id}"
        pin = json.dumps({'type': 'pin', 'message_id': message_id, 'from': str(current_user.unique_id)})
        await redis_client.rpush(key, pin)
        await redis_client.expire(key, 86400)
        return {"ok": True}

    @router.post("/react")
    async def react_message(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        target_id = (payload or {}).get("target_id")
        message_id = (payload or {}).get("message_id")
        reaction = (payload or {}).get("reaction")
        if not target_id or not message_id or not reaction:
            raise HTTPException(400, detail="Неверные параметры")
        key = f"ws_message:{target_id}"
        react = json.dumps({'type': 'react', 'message_id': message_id, 'from': str(current_user.unique_id), 'reaction': reaction})
        await redis_client.rpush(key, react)
        await redis_client.expire(key, 86400)
        return {"ok": True}

    return router

