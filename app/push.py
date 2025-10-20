import os
import json
from typing import Optional, Dict, Any

from fastapi import HTTPException

try:
    from pywebpush import webpush, WebPushException
except Exception:  # optional dependency guard
    webpush = None
    WebPushException = Exception


def get_vapid_keys() -> Dict[str, Optional[str]]:
    return {
        "public": os.getenv("VAPID_PUBLIC_KEY"),
        "private": os.getenv("VAPID_PRIVATE_KEY"),
        "subject": os.getenv("VAPID_SUBJECT", "mailto:admin@pixeltoo.ru"),
    }


def validate_subscription(subscription: Dict[str, Any]) -> None:
    if not isinstance(subscription, dict):
        raise HTTPException(status_code=400, detail="subscription должен быть объектом")
    endpoint = subscription.get("endpoint")
    keys = subscription.get("keys") or {}
    p256dh = keys.get("p256dh")
    auth = keys.get("auth")
    if not endpoint or not isinstance(endpoint, str) or len(endpoint) < 10:
        raise HTTPException(status_code=400, detail="Некорректный endpoint в подписке")
    if not p256dh or not auth:
        raise HTTPException(status_code=400, detail="Отсутствуют ключи p256dh/auth в подписке")


def send_webpush(subscription: Dict[str, Any], payload: Dict[str, Any]) -> None:
    if webpush is None:
        raise HTTPException(status_code=500, detail="pywebpush не установлен на сервере")
    vapid = get_vapid_keys()
    if not vapid["public"] or not vapid["private"]:
        raise HTTPException(status_code=500, detail="VAPID ключи не настроены")
    try:
        webpush(
            subscription_info=subscription,
            data=json.dumps(payload),
            vapid_private_key=vapid["private"],
            vapid_claims={"sub": vapid["subject"]},
        )
    except WebPushException as e:
        # Let caller handle specific cleanup on 410/404
        raise HTTPException(status_code=502, detail=f"WebPush ошибка: {str(e)}")








