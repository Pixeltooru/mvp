from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession


def build_router(get_db_dep, get_current_user_dep, encrypt_data):
    router = APIRouter(prefix="/avatar", tags=["avatar"])

    @router.post("/upload")
    async def upload_avatar(file: UploadFile = File(...), current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        content = await file.read()
        if len(content) > 2 * 1024 * 1024:
            raise HTTPException(400, detail="Слишком большой файл (макс 2МБ)")
        enc = encrypt_data(content.decode('latin1'))
        current_user.encrypted_avatar = enc
        current_user.avatar_mime = file.content_type
        await db.begin()
        await db.merge(current_user)
        await db.commit()
        return {"ok": True}

    @router.delete("/")
    async def delete_avatar(current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        await db.begin()
        current_user.encrypted_avatar = None
        current_user.avatar_mime = None
        await db.merge(current_user)
        await db.commit()
        return {"ok": True}

    @router.get("/{user_unique_id}")
    async def get_avatar(user_unique_id: str, current_user = Depends(get_current_user_dep), db: AsyncSession = Depends(get_db_dep)):
        # Возвращаем зашифрованный аватар и mime; клиент сам расшифрует
        from sqlalchemy import select
        stmt = select(type(current_user)).filter(type(current_user).unique_id == int(user_unique_id))
        res = await db.execute(stmt)
        target = res.scalar_one_or_none()
        if not target or not target.encrypted_avatar:
            raise HTTPException(404, detail="Аватар не найден")
        return {"ok": True, "encrypted_avatar": target.encrypted_avatar, "mime": target.avatar_mime}

    return router

