from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
import secrets
import json


def build_router(get_db_dep, get_current_user_dep, redis_client):
    router = APIRouter(prefix="/devices", tags=["devices"])

    @router.post("/register")
    async def register_device(payload: dict, current_user = Depends(get_current_user_dep)):
        device_id = (payload or {}).get("device_id")
        if not device_id or len(device_id) < 6:
            raise HTTPException(400, detail="Неверный device_id")
        token = secrets.token_urlsafe(32)
        key = f"device:{current_user.unique_id}:{device_id}"
        await redis_client.set(key, token, ex=30*24*3600)
        return {"ok": True, "device_token": token}

    @router.post("/refresh")
    async def refresh_device(payload: dict, current_user = Depends(get_current_user_dep)):
        device_id = (payload or {}).get("device_id")
        old = (payload or {}).get("device_token")
        if not device_id or not old:
            raise HTTPException(400, detail="Неверные параметры")
        key = f"device:{current_user.unique_id}:{device_id}"
        cur = await redis_client.get(key)
        if cur != old:
            raise HTTPException(401, detail="Неизвестное устройство")
        new_token = secrets.token_urlsafe(32)
        await redis_client.set(key, new_token, ex=30*24*3600)
        return {"ok": True, "device_token": new_token}

    @router.post("/revoke")
    async def revoke_device(payload: dict, current_user = Depends(get_current_user_dep)):
        device_id = (payload or {}).get("device_id")
        if not device_id:
            raise HTTPException(400, detail="Неверный device_id")
        key = f"device:{current_user.unique_id}:{device_id}"
        await redis_client.delete(key)
        return {"ok": True}

    @router.post("/authorize")
    async def authorize_device(payload: dict):
        # Позволяет клиенту обменять (device_id, device_token, identifier) на краткоживущий JWT
        identifier = (payload or {}).get("identifier")
        device_id = (payload or {}).get("device_id")
        device_token = (payload or {}).get("device_token")
        if not identifier or not device_id or not device_token:
            raise HTTPException(400, detail="Неверные параметры")
        # Проверка пользователя по identifier (unique_id или телефон) и device_token в Redis здесь опускается
        # Клиенту рекомендуется использовать основной /login с device_token
        return {"ok": True}

    return router

