# MVP Flutter Client

Полнофункциональный Flutter-клиент для Melo Voice Project с поддержкой E2E-шифрования, WebRTC и кросс-платформенности (Android, Windows, Web).

## Возможности

- ✅ **Регистрация и авторизация** с автоматической генерацией E2E ключей
- ✅ **E2E шифрование** сообщений (RSA 2048)
- ✅ **WebRTC** аудио/видео звонки
- ✅ **WebSocket** для real-time сообщений
- ✅ **Чаты** (личные и групповые)
- ✅ **Контакты** и подписки
- ✅ **Профили** с аватарами
- ✅ **Push-уведомления**
- ✅ **Адаптивный UI** для всех платформ

## Установка

### 1. Установите зависимости

```bash
cd flutter/mvp
flutter pub get
```

### 2. Настройка конфигурации

Отредактируйте `lib/config.dart`:

```dart
class AppConfig {
  static const String httpBase = 'https://pixeltoo.ru:8088';
  static const String wsBase = 'wss://pixeltoo.ru:8089';
}
```

### 3. Запуск

#### Android
```bash
flutter run -d android
```

#### Windows
```bash
flutter run -d windows
```

#### Web
```bash
flutter run -d chrome
```

## Архитектура

### Структура проекта

```
lib/
├── config.dart              # Конфигурация (API endpoints)
├── main.dart                # Точка входа
├── router.dart              # Навигация (go_router)
├── screens/                 # Экраны приложения
│   ├── login_screen.dart
│   ├── register_screen.dart
│   ├── chat_list_screen.dart
│   ├── chat_screen.dart
│   ├── call_screen.dart     # WebRTC звонки
│   └── profile_screen.dart
├── services/                # Сервисы
│   ├── api_client.dart      # HTTP API клиент
│   ├── ws_client.dart       # WebSocket клиент
│   ├── e2e_service.dart     # E2E шифрование
│   └── webrtc_service.dart  # WebRTC
└── state/                   # State management (Riverpod)
    ├── auth_provider.dart
    └── theme_provider.dart
```

### Основные компоненты

#### 1. E2E Шифрование (`e2e_service.dart`)

- Генерация RSA 2048 ключей при регистрации
- Автоматическое шифрование/расшифровка сообщений
- Безопасное хранение приватного ключа локально

```dart
final e2e = E2EService();
await e2e.generateKeyPair();
final encrypted = e2e.encryptMessage('Hello', recipientPublicKey);
final decrypted = e2e.decryptMessage(encrypted);
```

#### 2. WebRTC (`webrtc_service.dart`)

- Аудио/видео звонки
- Обработка ICE candidates
- Управление медиа-потоками

```dart
final webrtc = WebRTCService();
await webrtc.initLocalStream(video: true, audio: true);
final offer = await webrtc.createOffer();
```

#### 3. API Client (`api_client.dart`)

Полная интеграция со всеми эндпоинтами сервера:

- Авторизация: `/register`, `/login`
- Профили: `/profile`
- Контакты: `/contacts`, `/subscribe`, `/confirm_subscribe`
- Чаты: `/chats`, `/chats/{id}/members`
- Сообщения: `/messages/send`, `/messages/history/*`
- E2E ключи: `/e2e/public_key`, `/e2e/secret_key`
- WebRTC: `/ice_servers`
- Аватары: `/avatars/upload`, `/avatars`

#### 4. WebSocket Client (`ws_client.dart`)

- Real-time сообщения
- WebRTC сигналинг
- Автоматическое переподключение

## Использование

### Регистрация

```dart
final authNotifier = ref.read(authStateProvider.notifier);
final result = await authNotifier.register(
  phone: '+79991234567',
  password: 'secure_password',
  name: 'John Doe',
  nickname: 'johndoe',
);
```

**Что происходит:**
1. Генерируются RSA ключи (2048 бит)
2. Создается 16-символьный hex `device_id`
3. Публичный ключ отправляется на сервер
4. Приватный ключ сохраняется локально

### Логин

```dart
final ok = await authNotifier.login(
  identifier: '+79991234567', // или unique_id
  password: 'secure_password',
);
```

**Автоматически:**
- Загружается сохраненный приватный ключ
- Используется сохраненный `device_id`
- Обновляется публичный E2E ключ на сервере

### Отправка зашифрованного сообщения

```dart
// Получаем публичный ключ получателя
final recipientKey = e2e.parsePublicKeyFromPem(recipientPublicKeyPem);

// Шифруем сообщение
final encrypted = e2e.encryptMessage('Hello!', recipientKey);

// Отправляем через API
await api.sendMessage(
  targetId: '12345678',
  data: encrypted,
);
```

### Инициация видео-звонка

```dart
context.push('/call/${targetId}?video=true&initiator=true');
```

## Безопасность

### E2E Шифрование

- **RSA 2048** для шифрования сообщений
- **OAEP padding** для защиты от атак
- **Приватный ключ** хранится только локально в `SharedPreferences`
- **Публичный ключ** на сервере зашифрован AES-256-GCM

### Device ID

- Генерируется криптографически стойким генератором (`Random.secure()`)
- 16 hex символов (64 бита энтропии)
- Сохраняется локально для повторного входа

### CSRF Protection

- CSRF токен получается при логине
- Автоматически добавляется к запросам подписки

## Платформы

### Android

**Разрешения** (`android/app/src/main/AndroidManifest.xml`):

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.CAMERA" />
<uses-permission android:name="android.permission.RECORD_AUDIO" />
<uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
```

**Минимальная версия:** Android 5.0 (API 21)

### Windows

**Требования:**
- Windows 10/11
- Visual Studio 2019+ (для сборки)

**Сборка:**
```bash
flutter build windows --release
```

### Web

**Ограничения:**
- WebRTC требует HTTPS
- Некоторые функции могут быть недоступны (например, фоновые уведомления)

**Сборка:**
```bash
flutter build web --release
```

## Troubleshooting

### Ошибка "Device ID должен быть 16-значной hex-строкой"

**Решение:** Обновите клиент - новая версия автоматически генерирует корректный `device_id`.

### WebRTC не работает

**Проверьте:**
1. Разрешения на камеру/микрофон
2. HTTPS соединение (для Web)
3. ICE серверы доступны (`/ice_servers`)

### Сообщения не расшифровываются

**Причины:**
1. Приватный ключ утерян (переустановка приложения)
2. Публичный ключ получателя устарел

**Решение:** Перелогиниться для обновления ключей.

## Разработка

### Добавление нового экрана

1. Создайте файл в `lib/screens/`
2. Добавьте маршрут в `lib/router.dart`
3. Используйте `ConsumerStatefulWidget` для доступа к Riverpod

### Добавление API метода

1. Добавьте метод в `lib/services/api_client.dart`
2. Используйте существующий `_dio` клиент
3. Обрабатывайте ошибки через `try-catch`

## Лицензия

Proprietary - Melo Voice Project

## Поддержка

Для вопросов и багов создавайте issue в репозитории.
