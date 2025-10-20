# Анализ шифрования данных в MVP сервере

## Стратегия: "Сервер ничего не знает о вас!"

### Текущее состояние шифрования

#### ✅ Данные, которые УЖЕ шифруются (MySQL):

**Таблица `users`:**
- `encrypted_phone` - телефон (шифруется AES-256-GCM)
- `encrypted_name` - имя (шифруется AES-256-GCM)
- `encrypted_nickname` - никнейм (шифруется AES-256-GCM)
- `encrypted_username` - username (шифруется AES-256-GCM)
- `encrypted_bio` - биография (шифруется AES-256-GCM)
- `encrypted_avatar` - аватар (шифруется AES-256-GCM)
- `encrypted_device_id` - ID устройства (шифруется AES-256-GCM)
- `hashed_password` - пароль (bcrypt hash)
- `hashed_phone` - хеш телефона для поиска (SHA-256)

**Таблица `e2e_keys`:**
- `encrypted_public_key` - публичный E2E ключ (шифруется AES-256-GCM)

**Таблица `secret_e2e_keys`:**
- `client_encrypted_secret` - секретный ключ (зашифрован на клиенте, сервер не расшифровывает)

---

#### ❌ Данные, которые НЕ шифруются (MySQL):

**Таблица `users`:**
- `unique_id` - уникальный ID (8 цифр) - **НЕ ТРЕБУЕТ ШИФРОВАНИЯ** (публичный идентификатор)
- `avatar_mime` - MIME тип аватара - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `last_activity` - время последней активности - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `e2e_key_updated` - время обновления E2E ключа - **ТРЕБУЕТ ШИФРОВАНИЯ**

**Таблица `chats`:**
- `name` - название чата/канала - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `type` - тип (chat/channel) - можно не шифровать (метаданные)
- `owner_id` - ID владельца - можно не шифровать (связь)
- `created_at` - время создания - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `is_public` - публичный ли - можно не шифровать (метаданные)
- `invite_code` - код приглашения - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `slow_mode_seconds` - режим slow mode - можно не шифровать (настройка)

**Таблица `subscriptions`:**
- `status` - статус подписки - можно не шифровать (метаданные)

**Таблица `chat_members`:**
- `role` - роль участника - можно не шифровать (метаданные)
- `joined_at` - время присоединения - **ТРЕБУЕТ ШИФРОВАНИЯ**

**Таблица `user_sessions`:**
- `session_token` - JTI токена - **НЕ ТРЕБУЕТ ШИФРОВАНИЯ** (уже хеш)
- `device_type` - тип устройства - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `device_name` - название устройства - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `ip_address` - IP адрес - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `user_agent` - User-Agent - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `created_at` - время создания - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `last_activity` - последняя активность - **ТРЕБУЕТ ШИФРОВАНИЯ**

**Таблица `user_statuses`:**
- `status` - статус (online/offline/away) - можно не шифровать (метаданные)
- `last_seen` - время последнего визита - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `is_typing_in_chat` - ID чата где печатает - можно не шифровать (временные данные)
- `typing_started_at` - время начала печати - можно не шифровать (временные данные)
- `updated_at` - время обновления - **ТРЕБУЕТ ШИФРОВАНИЯ**

**Таблица `message_read_statuses`:**
- `last_read_message_id` - UUID последнего прочитанного - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `read_at` - время прочтения - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `updated_at` - время обновления - **ТРЕБУЕТ ШИФРОВАНИЯ**

---

#### ❌ Данные в Redis, которые НЕ шифруются:

**Критичные данные:**
- `csrf:{user_id}` - CSRF токен - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `device:{user_id}:{device_id}` - device token для auto-login - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `push:{user_id}` - push подписка (JSON с endpoint/subscription) - **ТРЕБУЕТ ШИФРОВАНИЯ**
- `ws_message:{user_id}` - очередь сообщений (JSON с зашифрованными payload) - **УЖЕ ЗАШИФРОВАНО НА КЛИЕНТЕ**
- `history:{user_id}:{target_id}` - история сообщений DM - **УЖЕ ЗАШИФРОВАНО НА КЛИЕНТЕ**
- `history:chat:{chat_id}` - история сообщений чата - **УЖЕ ЗАШИФРОВАНО НА КЛИЕНТЕ**

**Временные/служебные данные (можно не шифровать):**
- `otp:{phone}` - OTP коды (временные)
- `pending_sub:{user_id}:{target_id}` - ожидающие подписки
- `secret_sub:{user_id}:{target_id}` - секретные подписки
- `rate_limit:{ip}:{ua_hash}` - лимиты запросов
- `block:{ip}:{ua_hash}` - блокировки IP
- `failed_login:{ip}` - неудачные попытки входа
- `call_pending:{user_id}` - ожидающие звонки
- `jwt_blacklist:{jti}` - черный список JWT
- `typing:{chat_id}:{user_id}` - индикатор печати
- `unique_id_lock` - блокировка генерации ID

---

## План реализации шифрования

### 1. MySQL - Новые зашифрованные поля

Добавить зашифрованные версии полей:

**users:**
- `encrypted_avatar_mime` (вместо `avatar_mime`)
- `encrypted_last_activity` (вместо `last_activity` - хранить как строку ISO)
- `encrypted_e2e_key_updated` (вместо `e2e_key_updated` - хранить как строку ISO)

**chats:**
- `encrypted_name` (вместо `name`)
- `encrypted_created_at` (вместо `created_at`)
- `encrypted_invite_code` (вместо `invite_code`)

**chat_members:**
- `encrypted_joined_at` (вместо `joined_at`)

**user_sessions:**
- `encrypted_device_type` (вместо `device_type`)
- `encrypted_device_name` (вместо `device_name`)
- `encrypted_ip_address` (вместо `ip_address`)
- `encrypted_user_agent` (вместо `user_agent`)
- `encrypted_created_at` (вместо `created_at`)
- `encrypted_last_activity` (вместо `last_activity`)

**user_statuses:**
- `encrypted_last_seen` (вместо `last_seen`)
- `encrypted_updated_at` (вместо `updated_at`)

**message_read_statuses:**
- `encrypted_last_read_message_id` (вместо `last_read_message_id`)
- `encrypted_read_at` (вместо `read_at`)
- `encrypted_updated_at` (вместо `updated_at`)

### 2. Redis - Шифрование значений

Шифровать значения в Redis для ключей:
- `csrf:{user_id}` - шифровать CSRF токен
- `device:{user_id}:{device_id}` - шифровать device token
- `push:{user_id}` - шифровать JSON с push подпиской

### 3. Миграция существующих данных

Создать скрипт миграции, который:
1. Читает незашифрованные данные
2. Шифрует их с помощью ENCRYPTION_KEY
3. Сохраняет в новые зашифрованные поля
4. Опционально удаляет старые незашифрованные поля

---

## Преимущества реализации

1. **Zero-knowledge сервер**: Сервер не может прочитать личные данные без ключа
2. **Защита от утечек БД**: Даже при компрометации БД данные остаются зашифрованными
3. **Соответствие стратегии**: "Сервер ничего не знает о вас!"
4. **Ротация ключей**: Уже реализована функция `rotate_encryption_key()`
5. **E2E шифрование**: Сообщения уже зашифрованы на клиенте

---

## Технические детали

**Алгоритм шифрования:** AES-256-GCM
**Ключ:** 32 байта (256 бит) из `ENCRYPTION_KEY_STR` в .env
**Формат:** base64(nonce[12] + ciphertext + tag[16])
**Функции:** `encrypt_data()` и `decrypt_data()` в main.py
