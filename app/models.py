from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base


Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    unique_id = Column(Integer, unique=True, index=True)
    hashed_phone = Column(String(64), unique=True, index=True, nullable=True)
    encrypted_phone = Column(Text, nullable=True)
    encrypted_name = Column(Text, nullable=True)
    encrypted_nickname = Column(Text, nullable=True)
    encrypted_username = Column(Text, nullable=True)
    encrypted_bio = Column(Text, nullable=True)
    encrypted_avatar = Column(Text, nullable=True)
    avatar_mime = Column(String(64), nullable=True)  # Deprecated: use encrypted_avatar_mime
    encrypted_avatar_mime = Column(Text, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    encrypted_device_id = Column(Text, nullable=True)
    e2e_key_updated = Column(DateTime, nullable=True)  # Deprecated: use encrypted_e2e_key_updated
    encrypted_e2e_key_updated = Column(Text, nullable=True)
    last_activity = Column(DateTime, nullable=False, default=datetime.utcnow)  # Deprecated: use encrypted_last_activity
    encrypted_last_activity = Column(Text, nullable=True)


class E2EKey(Base):
    __tablename__ = "e2e_keys"

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    encrypted_public_key = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow)


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    target_id = Column(Integer, ForeignKey('users.id'), index=True)
    status = Column(String(20), default='pending')  # pending, accepted, rejected


class SecretE2EKey(Base):
    __tablename__ = "secret_e2e_keys"

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    # Храним как есть: клиент-шифротекст (envelope), сервер не расшифровывает
    client_encrypted_secret = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow)


class Chat(Base):
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)  # Deprecated: use encrypted_name
    encrypted_name = Column(Text, nullable=True)
    type = Column(String(20), default='chat')  # chat | channel
    owner_id = Column(Integer, ForeignKey('users.id'), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)  # Deprecated: use encrypted_created_at
    encrypted_created_at = Column(Text, nullable=True)
    is_public = Column(Boolean, default=False)
    invite_code = Column(String(64), unique=True, nullable=True)  # Deprecated: use encrypted_invite_code
    encrypted_invite_code = Column(Text, nullable=True)
    slow_mode_seconds = Column(Integer, default=0)


class ChatMember(Base):
    __tablename__ = "chat_members"

    id = Column(Integer, primary_key=True, autoincrement=True)
    chat_id = Column(Integer, ForeignKey('chats.id'), index=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    role = Column(String(20), default='member')  # owner | admin | member
    joined_at = Column(DateTime, default=datetime.utcnow)  # Deprecated: use encrypted_joined_at
    encrypted_joined_at = Column(Text, nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    session_token = Column(String(255), unique=True, index=True)  # JTI токена
    device_type = Column(String(20), nullable=False)  # Deprecated: use encrypted_device_type
    encrypted_device_type = Column(Text, nullable=True)
    device_name = Column(String(100), nullable=True)  # Deprecated: use encrypted_device_name
    encrypted_device_name = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)  # Deprecated: use encrypted_ip_address
    encrypted_ip_address = Column(Text, nullable=True)
    user_agent = Column(Text, nullable=True)  # Deprecated: use encrypted_user_agent
    encrypted_user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)  # Deprecated: use encrypted_created_at
    encrypted_created_at = Column(Text, nullable=True)
    last_activity = Column(DateTime, default=datetime.utcnow)  # Deprecated: use encrypted_last_activity
    encrypted_last_activity = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)


class UserStatus(Base):
    __tablename__ = "user_statuses"

    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)
    status = Column(String(20), default='offline')  # online, offline, away
    last_seen = Column(DateTime, default=datetime.utcnow)  # Deprecated: use encrypted_last_seen
    encrypted_last_seen = Column(Text, nullable=True)
    is_typing_in_chat = Column(Integer, ForeignKey('chats.id'), nullable=True)  # ID чата где печатает
    typing_started_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)  # Deprecated: use encrypted_updated_at
    encrypted_updated_at = Column(Text, nullable=True)


class MessageReadStatus(Base):
    __tablename__ = "message_read_statuses"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True)
    chat_id = Column(Integer, ForeignKey('chats.id'), index=True)
    last_read_message_id = Column(String(36), nullable=False)  # Deprecated: use encrypted_last_read_message_id
    encrypted_last_read_message_id = Column(Text, nullable=True)
    read_at = Column(DateTime, default=datetime.utcnow)  # Deprecated: use encrypted_read_at
    encrypted_read_at = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)  # Deprecated: use encrypted_updated_at
    encrypted_updated_at = Column(Text, nullable=True)

