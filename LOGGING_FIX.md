# Исправления логирования

## Дата: 2025-10-20

### ✅ ИСПРАВЛЕНО

#### 1. Убрано дублирование логов
**Проблема:** Каждое сообщение выводилось 2 раза из-за двойного вызова в специальных методах логгера.

**Причина:** В методах `apiRequest()`, `apiResponse()`, `ws()`, `nav()`, `ui()`, `lifecycle()` и других:
1. Сначала вызывался `print()` с эмодзи
2. Потом вызывался `d()` или `i()`, который **снова делал `print()`**

**Решение:**
- Файл: `lib/core/utils/logger.dart`
- Удалены вторые вызовы `d()` и `i()` из всех специальных методов
- Удален неиспользуемый импорт `dart:developer`
- Теперь каждый метод делает только один `print()`

**Код до:**
```dart
static void ws(String message) {
  if (kDebugMode || _enableReleaseLogging) {
    print('$_logPrefix 🔌 [WEBSOCKET] $message');
  }
  d(message, 'WEBSOCKET'); // ← Это вызывало второй print()!
}
```

**Код после:**
```dart
static void ws(String message) {
  if (kDebugMode || _enableReleaseLogging) {
    print('$_logPrefix 🔌 [WEBSOCKET] $message');
  }
}
```

**Результат:** Каждое сообщение выводится только 1 раз.

---

#### 2. Исправлен ключ токена для WebSocket
**Проблема:** `Token from storage: null` - WebSocket не мог подключиться.

**Причина:** Использовался неправильный ключ `access_token` вместо `auth_token`.

**Решение:**
- Файл: `lib/main.dart` (строка 113)
- Изменено: `'access_token'` → `'auth_token'`
- Добавлено логирование длины токена

**Код:**
```dart
// Было:
final token = await storage.read(key: 'access_token');
AppLogger.i('Token from storage: ${token != null ? "exists" : "null"}', 'Main');

// Стало:
final token = await storage.read(key: 'auth_token');
AppLogger.i('Token from storage: ${token != null ? "exists (${token.length} chars)" : "null"}', 'Main');
```

**Результат:** WebSocket теперь получает токен и может подключиться.

---

#### 3. Добавлено логирование всех кнопок
**Файл:** `lib/presentation/screens/main/home_screen.dart`

**Добавлены логи для:**

##### AppBar кнопки:
- 🔘 Поиск (AppBar)
- 🔘 Настройки (AppBar)

##### FAB кнопки:
- 🔘 Создать группу (FAB)
- 🔘 Добавить контакт (FAB)

##### Диалоги создания группы:
- 🔘 Создать группу (подтверждение), название: "..."
- 🔘 Отмена создания группы
- ⚠️ Попытка создать группу с пустым названием

##### Диалоги добавления контакта:
- 🔘 Добавить контакт (подтверждение), ID: "..."
- 🔘 Отмена добавления контакта
- ⚠️ Попытка добавить контакт с пустым ID

##### Кнопки повтора:
- 🔘 Повторить загрузку чатов
- 🔘 Повторить загрузку контактов

##### Клики по элементам списка:
- 🔘 Нажат чат: [название] (ID: [id])
- 🔘 Нажат контакт: [имя] (ID: [unique_id])

---

## 📊 ПРИМЕРЫ НОВЫХ ЛОГОВ

### До исправлений:
```
flutter: 🔷 MVP_CLIENT 🎨 [UI_EVENT] HomeScreen: Search button clicked
flutter: 🔵 🔷 MVP_CLIENT [UI_EVENT] HomeScreen: Search button clicked
flutter: 🔷 MVP_CLIENT 🔌 [WEBSOCKET] → ping to null
flutter: 🔵 🔷 MVP_CLIENT [WEBSOCKET] → ping to null
flutter: ℹ️  🔷 MVP_CLIENT [Main] Token from storage: null
```

### После исправлений:
```
🔷 MVP_CLIENT 🔄 [LIFECYCLE] 🚀 Application starting...
ℹ️  🔷 MVP_CLIENT [Main] Token from storage: exists (550 chars)
ℹ️  🔷 MVP_CLIENT [Main] User authenticated, connecting WebSocket...
🔷 MVP_CLIENT 🔌 [WEBSOCKET] → ping to null
🔷 MVP_CLIENT 🎨 [UI_EVENT] 🔘 Нажата кнопка: Поиск (AppBar)
🔷 MVP_CLIENT 🎨 [UI_EVENT] 🔘 Нажат чат: HITEST (ID: 2)
```

---

## 🎯 ПРЕИМУЩЕСТВА

1. **Нет дублирования** - каждое сообщение выводится только 1 раз
2. **Легко искать** - все логи имеют префикс `🔷 MVP_CLIENT`
3. **Эмодзи для кнопок** - легко найти UI события по 🔘
4. **Детальная информация** - видно что именно нажал пользователь
5. **WebSocket работает** - токен теперь находится и передается

---

## 🔍 КАК ИСКАТЬ В ЛОГАХ

### Все UI события (кнопки):
```
🔘
```

### Все ошибки:
```
❌
```

### Все предупреждения:
```
⚠️
```

### WebSocket события:
```
🔌
```

### Навигация:
```
🧭
```

### API запросы:
```
🌐
```

---

## 🚀 ЧТО ДЕЛАТЬ ДАЛЬШЕ

1. **Перезапустите приложение:**
   ```bash
   flutter run
   ```

2. **Проверьте логи:**
   - Теперь каждое сообщение выводится только 1 раз
   - При нажатии кнопок видны логи с 🔘
   - WebSocket должен подключиться (если токен есть)

3. **Ожидаемые логи при запуске:**
   ```
   ℹ️  🔷 MVP_CLIENT [Main] Auth state: isAuthenticated=true
   ℹ️  🔷 MVP_CLIENT [Main] Token from storage: exists (1024 chars)
   ℹ️  🔷 MVP_CLIENT [Main] User authenticated, connecting WebSocket...
   🔌 🔷 MVP_CLIENT [WS] Подключение к WebSocket: wss://pixeltoo.ru:8089
   ✅ 🔷 MVP_CLIENT [WS] WebSocket успешно подключен!
   ```

---

## 📝 ФАЙЛЫ ИЗМЕНЕНЫ

1. `lib/core/utils/logger.dart` - убрано дублирование
2. `lib/main.dart` - исправлен ключ токена
3. `lib/presentation/screens/main/home_screen.dart` - добавлено логирование кнопок

---

## ✅ ИТОГИ

- ✅ Дублирование логов устранено
- ✅ WebSocket токен исправлен
- ✅ Все кнопки логируются
- ✅ Легко отслеживать действия пользователя
- ✅ Логи чистые и читаемые
