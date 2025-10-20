# 1. Сделайте .env недоступным для чтения
chmod 600 .env

# 2. Сгенерируйте ключи
chmod +x safe.sh
./safe.sh

# 3. Проверьте настройки
python3 -c "
import os, base64, sys
from dotenv import load_dotenv
load_dotenv(dotenv_path='.env')

errors = []
if not os.getenv('DB_URL'):
    errors.append('DB_URL не задан')
if not os.getenv('ENCRYPTION_KEY_STR'):
    errors.append('ENCRYPTION_KEY_STR не задан')
try:
    key = base64.urlsafe_b64decode(os.getenv('ENCRYPTION_KEY_STR', ''))
    if len(key) != 32:
        errors.append('ENCRYPTION_KEY_STR неверной длины')
except:
    errors.append('ENCRYPTION_KEY_STR некорректный base64')

if errors:
    print('❌ Ошибки конфигурации:')
    for e in errors:
        print(f'  - {e}')
    sys.exit(1)
else:
    print('✅ Конфигурация корректна')
"
python3 safe.py


# Генерация с проверкой и выводом информации
python3 -c "
import secrets
from dotenv import load_dotenv
load_dotenv(dotenv_path='.env')
key = secrets.token_urlsafe(32)
print(f'APP_SECRET_KEY={key}')
print(f'Длина: {len(key)} символов')
print(f'Байты: {len(key.encode())} байт')
print('✓ Готово для .env файла')
"