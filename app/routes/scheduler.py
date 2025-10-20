from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime
import json


def build_router(get_db_dep, get_current_user_dep, UserModel, redis_client):
    router = APIRouter(prefix="/schedule", tags=["schedule"])

    @router.post("/message")
    async def schedule_message(payload: dict, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        # payload: { target_id: str, when: iso, data: object }
        try:
            target_id = str(payload.get("target_id") or "")
            when_iso = payload.get("when")
            data = payload.get("data")
            if not target_id or not when_iso or not isinstance(data, dict):
                raise HTTPException(400, detail="Неверные параметры планирования")
            when = datetime.fromisoformat(when_iso)
            if when < datetime.utcnow():
                raise HTTPException(400, detail="Время должно быть в будущем")
            key = f"schedule:{current_user.unique_id}:{target_id}"
            entry = json.dumps({"when": when_iso, "data": data})
            await redis_client.rpush(key, entry)
            await redis_client.expire(key, 7*24*3600)
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, detail="Ошибка планирования сообщения")

    return router

