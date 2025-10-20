#!/bin/bash
# generate_keys.sh - Скрипт для генерации ключей для MVP

echo "=== Генерация ключей для MVP Server ==="

# Создание директории
sudo mkdir -p /var/mvp
sudo chown $USER:$USER /var/mvp
sudo chmod 700 /var/mvp

# Генерация ключа шифрования
echo "Генерируем ENCRYPTION_KEY_STR..."
ENCRYPTION_KEY=$(python3 -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
echo "ENCRYPTION_KEY_STR=$ENCRYPTION_KEY"

# Генерация JWT ключей
echo "Генерируем JWT ключи..."
python3 -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()

pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('/var/mvp/jwt_private.pem', 'wb') as f:
    f.write(pem_private)
with open('/var/mvp/jwt_public.pem', 'wb') as f:
    f.write(pem_public)

print('✓ JWT ключи сгенерированы и сохранены')
"

# Установка прав доступа
sudo chmod 600 /var/mvp/jwt_private.pem
sudo chmod 644 /var/mvp/jwt_public.pem
sudo chown root:root /var/mvp/jwt_private.pem

echo "=== Готово! ==="
echo "1. Скопируйте ENCRYPTION_KEY_STR в .env файл"
echo "2. Настройте DB_URL с безопасным паролем"
echo "3. Проверьте пути к SSL сертификатам"
echo "4. Перезапустите сервер"