-- Миграция для добавления таблиц сессий и статусов пользователей
-- Выполнить после обновления кода сервера

-- Таблица сессий пользователей
CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    device_type VARCHAR(20) NOT NULL DEFAULT 'unknown',
    device_name VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Индексы для таблицы сессий
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(is_active);

-- Таблица статусов пользователей
CREATE TABLE IF NOT EXISTS user_statuses (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(20) DEFAULT 'offline',
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_typing_in_chat INTEGER REFERENCES chats(id) ON DELETE SET NULL,
    typing_started_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для таблицы статусов
CREATE INDEX IF NOT EXISTS idx_user_statuses_status ON user_statuses(status);
CREATE INDEX IF NOT EXISTS idx_user_statuses_typing ON user_statuses(is_typing_in_chat);

-- Таблица статусов прочтения сообщений
CREATE TABLE IF NOT EXISTS message_read_statuses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    last_read_message_id VARCHAR(36) NOT NULL,
    read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, chat_id)
);

-- Индексы для таблицы статусов прочтения
CREATE INDEX IF NOT EXISTS idx_message_read_user_chat ON message_read_statuses(user_id, chat_id);
CREATE INDEX IF NOT EXISTS idx_message_read_chat ON message_read_statuses(chat_id);

-- Комментарии к таблицам
COMMENT ON TABLE user_sessions IS 'Активные сессии пользователей с информацией об устройствах';
COMMENT ON TABLE user_statuses IS 'Статусы пользователей (онлайн, оффлайн, печатает)';
COMMENT ON TABLE message_read_statuses IS 'Статусы прочтения сообщений в чатах';

-- Комментарии к полям
COMMENT ON COLUMN user_sessions.device_type IS 'Тип устройства: pc, phone, tablet, web';
COMMENT ON COLUMN user_sessions.session_token IS 'JTI токена для связи с JWT';
COMMENT ON COLUMN user_statuses.status IS 'Статус: online, offline, away';
COMMENT ON COLUMN user_statuses.is_typing_in_chat IS 'ID чата где пользователь печатает (NULL если не печатает)';
COMMENT ON COLUMN message_read_statuses.last_read_message_id IS 'UUID последнего прочитанного сообщения';
