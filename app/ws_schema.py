from pydantic import BaseModel, Field, validator
from typing import Optional, Literal, Any, Dict, List


class Envelope(BaseModel):
    type: Literal['ping', 'chat_message', 'msg_status', 'call_signal', 'get_history', 'typing']
    to: Optional[str] = Field(None, description="Целевой user_id (8-значный)")
    id: Optional[str] = Field(None, description="ID сообщения/звонка")
    signature: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None

    @validator('to')
    def validate_to(cls, v):
        if v is None:
            return v
        if not isinstance(v, str) or not v.isdigit() or len(v) != 8:
            raise ValueError('Неверный формат to')
        return v


class ChatMessagePayload(BaseModel):
    text: Optional[str] = None
    attachments: Optional[List[Dict[str, Any]]] = None


class MsgStatusPayload(BaseModel):
    message_id: str
    status: Literal['delivered', 'read']
    other: Optional[str] = None


class CallSignalPayload(BaseModel):
    signal: Literal['offer', 'answer', 'candidate', 'state']
    sdp: Optional[str] = None
    candidate: Optional[Dict[str, Any]] = None
    target_id: Optional[str] = None
    state: Optional[str] = None


def parse_envelope(data: Dict[str, Any]) -> Envelope:
    return Envelope(**data)


