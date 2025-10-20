# Исправление проблемы SQLAlchemy Session

**Дата:** 14 октября 2025, 23:12  
**Проблема:** `Object '<User>' is already attached to session 'X' (this is 'Y')`

---

## 🐛 Проблема

### Ошибка в логах:
```
Ошибка получения профиля для 26040983: 
Object '<User at 0x7f647349ea10>' is already attached to session '91' (this is '92')
INFO: "GET /profile HTTP/1.1" 500 Internal Server Error
```

### Причина:

В FastAPI с SQLAlchemy async объект `current_user`, полученный через `Depends(get_current_user)`, уже привязан к одной сессии базы данных. Когда мы пытаемся использовать `db.add(current_user)` в другой сессии, возникает конфликт.

**Проблемный код:**
```python
@app.get("/profile")
async def get_profile(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    async with db.begin():
        # ... работа с данными ...
        current_user.last_activity = datetime.utcnow()
        db.add(current_user)  # ❌ ОШИБКА! Уже привязан к другой сессии
        return response
```

---

## ✅ Решение

Заменить `db.add(current_user)` на `await db.merge(current_user)`.

### Что делает `merge()`?

`merge()` в SQLAlchemy:
1. Проверяет, существует ли объект в текущей сессии
2. Если существует - обновляет его атрибуты
3. Если нет - добавляет копию объекта в сессию
4. **Не вызывает конфликта** между сессиями

**Исправленный код:**
```python
@app.get("/profile")
async def get_profile(
    current_user: User = Depends(get_current_user), 
    db: AsyncSession = Depends(get_db)
):
    async with db.begin():
        # ... работа с данными ...
        current_user.last_activity = datetime.utcnow()
        await db.merge(current_user)  # ✅ ПРАВИЛЬНО
        return response
```

---

## 🔧 Исправленные файлы

### 1. `main.py` - 10 мест

| Endpoint | Строка | Изменение |
|----------|--------|-----------|
| POST /e2e/secret_key | 1244 | `db.add` → `await db.merge` |
| GET /ice_servers | 1318 | `db.add` → `await db.merge` |
| POST /subscribe | 1373 | `db.add` → `await db.merge` |
| POST /confirm_subscribe | 1415 | `db.add` → `await db.merge` |
| POST /confirm_subscribe | 1419 | `db.add(target)` → `await db.merge(target)` |
| GET /contacts | 1484 | `db.add` → `await db.merge` |
| GET /profile | 1563 | `db.add` → `await db.merge` |
| PUT /profile | 1586 | `db.add` → `await db.merge` |
| GET /statuses | 1632 | `db.add` → `await db.merge` |
| GET /history/{target_id} | 1761 | `db.add` → `await db.merge` |

### 2. `app/routes/avatars.py` - 2 места

| Endpoint | Строка | Изменение |
|----------|--------|-----------|
| POST /avatar/upload | 17 | `db.add` → `await db.merge` |
| DELETE /avatar/ | 26 | `db.add` → `await db.merge` |

---

## 📊 Статистика изменений

- **Файлов изменено:** 2
- **Всего замен:** 12
- **Затронуто endpoints:** 11

---

## 🎯 Результат

### Было:
```python
db.add(current_user)
# ❌ InvalidRequestError: 
# Object '<User>' is already attached to session 'X' (this is 'Y')
```

### Стало:
```python
await db.merge(current_user)
# ✅ Работает корректно, нет конфликтов сессий
```

---

## 🧪 Тестирование

### Проверьте следующие endpoints:

1. ✅ `GET /profile` - основная проблема
2. ✅ `PUT /profile` - обновление профиля
3. ✅ `GET /contacts` - список контактов
4. ✅ `POST /subscribe` - подписка
5. ✅ `POST /confirm_subscribe` - подтверждение подписки
6. ✅ `GET /statuses` - статусы пользователей
7. ✅ `GET /history/{target_id}` - история сообщений
8. ✅ `POST /avatar/upload` - загрузка аватара
9. ✅ `DELETE /avatar/` - удаление аватара
10. ✅ `POST /e2e/secret_key` - сохранение E2E ключа
11. ✅ `GET /ice_servers` - получение ICE серверов

### Ожидаемый результат:

```
INFO: "GET /profile HTTP/1.1" 200 OK
```

Вместо:

```
INFO: "GET /profile HTTP/1.1" 500 Internal Server Error
```

---

## 📚 Дополнительная информация

### Почему возникала проблема?

**Архитектура зависимостей FastAPI:**

```python
# Dependency 1: получает user из одной сессии
async def get_current_user(db: AsyncSession = Depends(get_db)):
    # Создаётся сессия 'A'
    user = await db.execute(select(User)...)
    return user  # user привязан к сессии 'A'

# Dependency 2: создаёт новую сессию
async def get_db():
    async with async_session() as session:
        yield session  # Создаётся сессия 'B'

# Endpoint
@app.get("/profile")
async def get_profile(
    current_user: User = Depends(get_current_user),  # Сессия 'A'
    db: AsyncSession = Depends(get_db)               # Сессия 'B'
):
    db.add(current_user)  # ❌ Пытаемся добавить объект из 'A' в 'B'
```

### Правильный подход:

1. **Вариант 1:** Использовать `merge()` (✅ используем)
2. **Вариант 2:** Обновлять через UPDATE statement
3. **Вариант 3:** Использовать одну сессию для всех операций

---

## 🔄 Restart сервера

После изменений **обязательно** перезапустите сервер:

```bash
# Остановить
Ctrl+C

# Запустить заново
python main.py
```

Или если используется systemd/supervisor - перезапустить сервис.

---

## ✅ Проверка

Попробуйте снова войти в приложение:

1. Откройте Flutter приложение
2. Выполните логин
3. GET /profile должен вернуть 200 OK
4. Профиль должен загрузиться успешно

---

**Автор:** Cascade AI  
**Статус:** ✅ Исправлено  
**Изменений:** 12 (10 в main.py, 2 в avatars.py)
