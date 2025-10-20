-- Миграция: Добавление зашифрованных полей
-- Стратегия: "Сервер ничего не знает о вас!"
-- Версия: 3.2.0
-- Дата: 2025-10-20

-- ============================================================
-- Таблица users
-- ============================================================

-- Добавляем зашифрованные поля для users
ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_avatar_mime TEXT AFTER avatar_mime;
ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_e2e_key_updated TEXT AFTER e2e_key_updated;
ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_last_activity TEXT AFTER last_activity;

-- Комментарии для документации
ALTER TABLE users MODIFY COLUMN avatar_mime VARCHAR(64) COMMENT 'Deprecated: use encrypted_avatar_mime';
ALTER TABLE users MODIFY COLUMN e2e_key_updated DATETIME COMMENT 'Deprecated: use encrypted_e2e_key_updated';
ALTER TABLE users MODIFY COLUMN last_activity DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_last_activity';

-- ============================================================
-- Таблица chats
-- ============================================================

-- Добавляем зашифрованные поля для chats
ALTER TABLE chats ADD COLUMN IF NOT EXISTS encrypted_name TEXT AFTER name;
ALTER TABLE chats ADD COLUMN IF NOT EXISTS encrypted_created_at TEXT AFTER created_at;
ALTER TABLE chats ADD COLUMN IF NOT EXISTS encrypted_invite_code TEXT AFTER invite_code;

-- Комментарии для документации
ALTER TABLE chats MODIFY COLUMN name VARCHAR(255) NOT NULL COMMENT 'Deprecated: use encrypted_name';
ALTER TABLE chats MODIFY COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_created_at';
ALTER TABLE chats MODIFY COLUMN invite_code VARCHAR(64) UNIQUE COMMENT 'Deprecated: use encrypted_invite_code';

-- ============================================================
-- Таблица chat_members
-- ============================================================

-- Добавляем зашифрованные поля для chat_members
ALTER TABLE chat_members ADD COLUMN IF NOT EXISTS encrypted_joined_at TEXT AFTER joined_at;

-- Комментарии для документации
ALTER TABLE chat_members MODIFY COLUMN joined_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_joined_at';

-- ============================================================
-- Таблица user_sessions
-- ============================================================

-- Добавляем зашифрованные поля для user_sessions
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS encrypted_device_type TEXT AFTER device_type;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS encrypted_device_name TEXT AFTER device_name;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS encrypted_ip_address TEXT AFTER ip_address;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS encrypted_user_agent TEXT AFTER user_agent;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS encrypted_created_at TEXT AFTER created_at;
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS encrypted_last_activity TEXT AFTER last_activity;

-- Комментарии для документации
ALTER TABLE user_sessions MODIFY COLUMN device_type VARCHAR(20) NOT NULL COMMENT 'Deprecated: use encrypted_device_type';
ALTER TABLE user_sessions MODIFY COLUMN device_name VARCHAR(100) COMMENT 'Deprecated: use encrypted_device_name';
ALTER TABLE user_sessions MODIFY COLUMN ip_address VARCHAR(45) COMMENT 'Deprecated: use encrypted_ip_address';
ALTER TABLE user_sessions MODIFY COLUMN user_agent TEXT COMMENT 'Deprecated: use encrypted_user_agent';
ALTER TABLE user_sessions MODIFY COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_created_at';
ALTER TABLE user_sessions MODIFY COLUMN last_activity DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_last_activity';

-- ============================================================
-- Таблица user_statuses
-- ============================================================

-- Добавляем зашифрованные поля для user_statuses
ALTER TABLE user_statuses ADD COLUMN IF NOT EXISTS encrypted_last_seen TEXT AFTER last_seen;
ALTER TABLE user_statuses ADD COLUMN IF NOT EXISTS encrypted_updated_at TEXT AFTER updated_at;

-- Комментарии для документации
ALTER TABLE user_statuses MODIFY COLUMN last_seen DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_last_seen';
ALTER TABLE user_statuses MODIFY COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_updated_at';

-- ============================================================
-- Таблица message_read_statuses
-- ============================================================

-- Добавляем зашифрованные поля для message_read_statuses
ALTER TABLE message_read_statuses ADD COLUMN IF NOT EXISTS encrypted_last_read_message_id TEXT AFTER last_read_message_id;
ALTER TABLE message_read_statuses ADD COLUMN IF NOT EXISTS encrypted_read_at TEXT AFTER read_at;
ALTER TABLE message_read_statuses ADD COLUMN IF NOT EXISTS encrypted_updated_at TEXT AFTER updated_at;

-- Комментарии для документации
ALTER TABLE message_read_statuses MODIFY COLUMN last_read_message_id VARCHAR(36) NOT NULL COMMENT 'Deprecated: use encrypted_last_read_message_id';
ALTER TABLE message_read_statuses MODIFY COLUMN read_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_read_at';
ALTER TABLE message_read_statuses MODIFY COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT 'Deprecated: use encrypted_updated_at';

-- ============================================================
-- Проверка результатов
-- ============================================================

-- Показать структуру таблиц для проверки
SHOW COLUMNS FROM users;
SHOW COLUMNS FROM chats;
SHOW COLUMNS FROM chat_members;
SHOW COLUMNS FROM user_sessions;
SHOW COLUMNS FROM user_statuses;
SHOW COLUMNS FROM message_read_statuses;

-- ============================================================
-- Примечания
-- ============================================================

-- 1. Старые поля помечены как Deprecated, но НЕ удалены
-- 2. Это обеспечивает обратную совместимость
-- 3. После миграции данных и проверки можно удалить старые поля
-- 4. Используйте скрипт migrate_encrypt_data.py для миграции данных
-- 5. Все новые поля имеют тип TEXT для хранения зашифрованных данных

-- ============================================================
-- Удаление старых полей (ОПЦИОНАЛЬНО, после проверки)
-- ============================================================

-- ВНИМАНИЕ: Выполняйте эти команды только после полной проверки!
-- Раскомментируйте и выполните только когда уверены:

-- ALTER TABLE users DROP COLUMN avatar_mime;
-- ALTER TABLE users DROP COLUMN e2e_key_updated;
-- -- НЕ удаляйте last_activity - может использоваться для индексов

-- ALTER TABLE chats DROP COLUMN name;
-- ALTER TABLE chats DROP COLUMN created_at;
-- ALTER TABLE chats DROP COLUMN invite_code;

-- ALTER TABLE chat_members DROP COLUMN joined_at;

-- ALTER TABLE user_sessions DROP COLUMN device_type;
-- ALTER TABLE user_sessions DROP COLUMN device_name;
-- ALTER TABLE user_sessions DROP COLUMN ip_address;
-- ALTER TABLE user_sessions DROP COLUMN user_agent;
-- ALTER TABLE user_sessions DROP COLUMN created_at;
-- ALTER TABLE user_sessions DROP COLUMN last_activity;

-- ALTER TABLE user_statuses DROP COLUMN last_seen;
-- ALTER TABLE user_statuses DROP COLUMN updated_at;

-- ALTER TABLE message_read_statuses DROP COLUMN last_read_message_id;
-- ALTER TABLE message_read_statuses DROP COLUMN read_at;
-- ALTER TABLE message_read_statuses DROP COLUMN updated_at;
