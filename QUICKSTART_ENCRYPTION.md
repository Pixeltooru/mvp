# Быстрый старт: Шифрование данных

## 🚀 За 5 минут

### Шаг 1: Резервная копия (1 мин)

```bash
# MySQL
mysqldump -u user -p mvp_db > backup_$(date +%Y%m%d).sql

# Redis (опционально)
redis-cli SAVE
cp /var/lib/redis/dump.rdb backup_redis_$(date +%Y%m%d).rdb
```

### Шаг 2: Добавить поля в БД (1 мин)

```bash
mysql -u user -p mvp_db < migration_add_encrypted_fields.sql
```

Или запустите сервер - поля добавятся автоматически:
```bash
python main.py
```

### Шаг 3: Тестовая миграция (1 мин)

```bash
python migrate_encrypt_data.py --dry-run
```

Проверьте вывод - что будет зашифровано.

### Шаг 4: Реальная миграция (1 мин)

```bash
python migrate_encrypt_data.py
```

Введите `yes` для подтверждения.

### Шаг 5: Проверка (1 мин)

```bash
# Проверьте логи
cat migration_encrypt.log | grep "Мигрировано"

# Проверьте БД
mysql -u user -p mvp_db -e "SELECT unique_id, encrypted_avatar_mime FROM users LIMIT 1;"

# Должны увидеть зашифрованные данные (base64 строки)
```

---

## ✅ Готово!

Все чувствительные данные теперь зашифрованы.

**Стратегия "Сервер ничего не знает о вас!" реализована!** 🔐

---

## 📚 Дополнительно

- **Полная инструкция:** [ENCRYPTION_IMPLEMENTATION.md](ENCRYPTION_IMPLEMENTATION.md)
- **Анализ:** [ENCRYPTION_ANALYSIS.md](ENCRYPTION_ANALYSIS.md)
- **Резюме:** [ENCRYPTION_SUMMARY.md](ENCRYPTION_SUMMARY.md)

---

## ⚠️ Важно

1. **Не удаляйте** `ENCRYPTION_KEY_STR` из `.env`
2. **Сохраните** резервные копии
3. **Проверьте** логи миграции
4. **Обновите** код приложения (см. документацию)

---

## 🆘 Проблемы?

```bash
# Откатить миграцию (из резервной копии)
mysql -u user -p mvp_db < backup_YYYYMMDD.sql

# Проверить ключ шифрования
python -c "import os; from dotenv import load_dotenv; load_dotenv(); print('OK' if os.getenv('ENCRYPTION_KEY_STR') else 'ERROR')"

# Посмотреть логи
tail -f migration_encrypt.log
tail -f mvp_server.log
```
