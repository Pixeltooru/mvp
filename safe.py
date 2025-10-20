import os, base64
from dotenv import load_dotenv
load_dotenv(dotenv_path='.env')

print('✓ DB_URL:', bool(os.getenv('DB_URL')))
print('✓ ENCRYPTION_KEY:', len(base64.urlsafe_b64decode(os.getenv('ENCRYPTION_KEY_STR', ''))) == 32)
print('✓ SSL files:', os.path.exists('/etc/letsencrypt/live/pixeltoo.ru/fullchain.pem'))
print('✓ JWT paths writable:', os.access('/var/mvp', os.W_OK))
