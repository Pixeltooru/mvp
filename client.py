import sys
import json
import requests
import websocket
import threading
import time
from datetime import datetime
import jwt
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QTabWidget, QPushButton, QLineEdit, QLabel, QTextEdit, 
                             QListWidget, QListWidgetItem, QMessageBox, QInputDialog)
from PyQt5.QtCore import Qt, QTimer, QSettings
from PyQt5.QtGui import QFont
from cryptography.fernet import Fernet
import base64
import os
import ssl
import logging
import random
import socket

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('melo_voice_client.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Конфигурация
BASE_URL = 'https://YouDomain:8088'
WS_URL = 'wss://YouDomain:8089'
SETTINGS_FILE = 'melo_voice_settings.ini'
REQUEST_TIMEOUT = 15
RETRY_DELAY = 5
MAX_RETRIES = 3
WS_RECONNECT_BASE_DELAY = 5
WS_RECONNECT_MAX_DELAY = 30
DISABLE_SSL_VERIFY = True

class MeloVoiceClient(QMainWindow):
    def __init__(self):
        super().__init__()
        logger.debug("Инициализация MeloVoiceClient")
        self.token = None
        self.user_id = None
        self.e2e_key = None
        self.csrf_token = None
        self.cipher = None
        self.ws = None
        self.contacts = []
        self.pending_contacts = []
        self.current_call_id = None
        self.logs = []
        self.settings = QSettings(SETTINGS_FILE, QSettings.IniFormat)
        self.last_request_time = 0
        self.ws_reconnect_attempts = 0
        try:
            self.load_session()
            self.init_ui()
            QApplication.processEvents()
            self.show()
            self.raise_()
            self.repaint()
            logger.debug("UI успешно инициализирован")
            if self.token and self.e2e_key and self.is_token_valid():
                QTimer.singleShot(100, self.connect_websocket)
                QTimer.singleShot(200, self.load_contacts)
            else:
                logger.warning("Токен или e2e_key отсутствует, или токен недействителен")
                self.show_auth_ui()
        except Exception as e:
            logger.error(f"Ошибка при инициализации клиента: {str(e)}")
            self.show_notification(f"Ошибка инициализации: {str(e)}")
            raise

    def is_token_valid(self):
        """Проверяет, действителен ли токен."""
        try:
            if not self.token:
                return False
            decoded = jwt.decode(self.token, options={"verify_signature": False})
            exp = decoded.get('exp')
            if exp and exp < int(time.time()):
                logger.warning("Токен истек")
                return False
            return True
        except jwt.InvalidTokenError as e:
            logger.error(f"Недействительный токен: {str(e)}")
            return False

    def init_ui(self):
        logger.debug("Инициализация UI")
        try:
            self.setWindowTitle('Melo Voice')
            self.setMinimumSize(360, 640)
            self.setStyleSheet("""
                QMainWindow, QWidget { background-color: #1a1a2e; color: #ffffff; }
                QLineEdit, QTextEdit { 
                    background-color: #2a2a3e; 
                    color: #ffffff; 
                    border: 1px solid #3a3a4e; 
                    border-radius: 5px; 
                    padding: 5px; 
                    font-size: 16px;
                }
                QPushButton { 
                    background-color: #3a7bd5; 
                    color: #ffffff; 
                    border: none; 
                    border-radius: 5px; 
                    padding: 10px; 
                    font-size: 16px;
                }
                QPushButton:hover { background-color: #4a8be5; }
                QPushButton:pressed { background-color: #2a5bb5; }
                QListWidget { 
                    background-color: #2a2a3e; 
                    color: #ffffff; 
                    border: none; 
                    font-size: 16px;
                }
                QListWidget::item { padding: 10px; }
                QListWidget::item:selected { background-color: #3a7bd5; }
                QLabel { font-size: 16px; }
                QTabWidget::pane { border: none; }
                QTabWidget::tab-bar { alignment: center; }
                QTabBar::tab { 
                    background: #2a2a3e; 
                    color: #ffffff; 
                    padding: 10px; 
                    border-radius: 5px;
                    margin: 2px;
                }
                QTabBar::tab:selected { background: #3a7bd5; }
            """)

            central_widget = QWidget()
            self.setCentralWidget(central_widget)
            main_layout = QVBoxLayout(central_widget)
            main_layout.setSpacing(10)
            main_layout.setContentsMargins(10, 10, 10, 10)

            navbar = QHBoxLayout()
            self.user_label = QLabel(f'ID: {self.user_id}' if self.user_id else 'Не авторизован')
            self.user_label.setStyleSheet("font-size: 18px; font-weight: bold;")
            logout_btn = QPushButton('Выход')
            logout_btn.clicked.connect(self.logout)
            navbar.addWidget(self.user_label)
            navbar.addStretch()
            navbar.addWidget(logout_btn)
            main_layout.addLayout(navbar)

            self.tabs = QTabWidget()
            self.tabs.setStyleSheet("QTabBar::tab { min-width: 100px; }")
            main_layout.addWidget(self.tabs)

            if not self.token or not self.e2e_key or not self.is_token_valid():
                self.show_auth_ui()
            else:
                self.show_main_ui()

            logger.debug("UI успешно настроен")
            QApplication.processEvents()
        except Exception as e:
            logger.error(f"Ошибка настройки UI: {str(e)}")
            raise

    def show_auth_ui(self):
        logger.debug("Отображение UI авторизации")
        try:
            self.tabs.clear()
            auth_widget = QWidget()
            auth_layout = QVBoxLayout(auth_widget)
            auth_layout.setSpacing(10)
            auth_layout.setContentsMargins(10, 10, 10, 10)

            login_widget = QWidget()
            login_layout = QVBoxLayout(login_widget)
            login_layout.addWidget(QLabel('Вход'))
            self.login_identifier = QLineEdit()
            self.login_identifier.setPlaceholderText('ID или +79123456789')
            self.login_password = QLineEdit()
            self.login_password.setPlaceholderText('Пароль')
            self.login_password.setEchoMode(QLineEdit.Password)
            self.otp_input = QLineEdit()
            self.otp_input.setPlaceholderText('Код подтверждения')
            self.otp_input.setVisible(False)
            generate_otp_btn = QPushButton('Запросить код')
            generate_otp_btn.clicked.connect(self.generate_otp)
            login_btn = QPushButton('Войти')
            login_btn.clicked.connect(self.login)
            login_layout.addWidget(self.login_identifier)
            login_layout.addWidget(self.login_password)
            login_layout.addWidget(self.otp_input)
            login_layout.addWidget(generate_otp_btn)
            login_layout.addWidget(login_btn)
            self.tabs.addTab(login_widget, 'Вход')

            register_widget = QWidget()
            register_layout = QVBoxLayout(register_widget)
            register_layout.addWidget(QLabel('Регистрация'))
            self.register_phone = QLineEdit()
            self.register_phone.setPlaceholderText('+79123456789 или 89123456789')
            self.register_name = QLineEdit()
            self.register_name.setPlaceholderText('Ваше имя')
            self.register_nickname = QLineEdit()
            self.register_nickname.setPlaceholderText('Ваш никнейм')
            self.register_password = QLineEdit()
            self.register_password.setPlaceholderText('Пароль')
            self.register_password.setEchoMode(QLineEdit.Password)
            self.register_confirm_password = QLineEdit()
            self.register_confirm_password.setPlaceholderText('Подтвердите пароль')
            self.register_confirm_password.setEchoMode(QLineEdit.Password)
            register_btn = QPushButton('Зарегистрироваться')
            register_btn.clicked.connect(self.register)
            register_layout.addWidget(self.register_phone)
            register_layout.addWidget(self.register_name)
            register_layout.addWidget(self.register_nickname)
            register_layout.addWidget(self.register_password)
            register_layout.addWidget(self.register_confirm_password)
            register_layout.addWidget(register_btn)
            self.tabs.addTab(register_widget, 'Регистрация')

            self.logs_text = QTextEdit()
            self.logs_text.setReadOnly(True)
            self.tabs.addTab(self.logs_text, 'Логи')

            logger.debug("UI авторизации успешно отображен")
            QApplication.processEvents()
            self.show()
            self.raise_()
            self.repaint()
        except Exception as e:
            logger.error(f"Ошибка отображения UI авторизации: {str(e)}")
            self.show_notification(f"Ошибка UI авторизации: {str(e)}")

    def show_main_ui(self):
        logger.debug("Отображение основного UI")
        try:
            self.tabs.clear()
            main_widget = QWidget()
            main_layout = QHBoxLayout(main_widget)
            main_layout.setSpacing(10)
            main_layout.setContentsMargins(10, 10, 10, 10)

            contacts_widget = QWidget()
            contacts_layout = QVBoxLayout(contacts_widget)
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText('Поиск...')
            self.search_input.textChanged.connect(self.search_contacts)
            add_contact_btn = QPushButton('Добавить контакт')
            add_contact_btn.clicked.connect(self.show_add_contact_dialog)
            self.contacts_list = QListWidget()
            self.contacts_list.itemDoubleClicked.connect(self.start_call_from_list)
            contacts_layout.addWidget(self.search_input)
            contacts_layout.addWidget(add_contact_btn)
            contacts_layout.addWidget(self.contacts_list)
            self.tabs.addTab(contacts_widget, 'Контакты')

            pending_widget = QWidget()
            pending_layout = QVBoxLayout(pending_widget)
            self.no_pending_label = QLabel('Нет ожидающих запросов')
            self.pending_list = QListWidget()
            pending_layout.addWidget(self.no_pending_label)
            pending_layout.addWidget(self.pending_list)
            self.tabs.addTab(pending_widget, 'Ожидающие')

            call_widget = QWidget()
            call_layout = QVBoxLayout(call_widget)
            self.call_status = QLabel('Выберите контакт для звонка')
            self.call_user = QLabel('')
            self.end_call_btn = QPushButton('Завершить')
            self.end_call_btn.clicked.connect(self.end_call)
            self.end_call_btn.setVisible(False)
            call_layout.addWidget(self.call_status)
            call_layout.addWidget(self.call_user)
            call_layout.addWidget(self.end_call_btn)
            self.tabs.addTab(call_widget, 'Вызов')

            self.logs_text = QTextEdit()
            self.logs_text.setReadOnly(True)
            self.tabs.addTab(self.logs_text, 'Логи')

            logger.debug("Основной UI успешно отображен")
            QApplication.processEvents()
            self.show()
            self.raise_()
            self.repaint()
        except Exception as e:
            logger.error(f"Ошибка отображения основного UI: {str(e)}")
            self.show_notification(f"Ошибка основного UI: {str(e)}")

    def log(self, message):
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.logs.append(f'[{timestamp}] {message}')
            if len(self.logs) > 100:
                self.logs = self.logs[-100:]
            QTimer.singleShot(0, lambda: self.logs_text.setText('\n'.join(self.logs)))
            logger.debug(f'Лог: {message}')
            QApplication.processEvents()
        except Exception as e:
            logger.error(f'Ошибка логирования: {str(e)}')

    def show_notification(self, message):
        try:
            QMessageBox.information(self, 'Уведомление', message)
            logger.debug(f'Уведомление: {message}')
            QApplication.processEvents()
            self.show()
            self.raise_()
            self.repaint()
        except Exception as e:
            logger.error(f'Ошибка уведомления: {str(e)}')

    def load_session(self):
        try:
            self.user_id = self.settings.value('user_id', type=str)
            self.token = self.settings.value('token', type=str)
            self.e2e_key = self.settings.value('e2e_key', type=str)
            self.csrf_token = self.settings.value('csrf_token', type=str)
            if self.e2e_key:
                try:
                    self.cipher = Fernet(self.e2e_key.encode())
                    logger.debug(f'Сессия загружена: user_id={self.user_id}, token={self.token}, e2e_key={self.e2e_key}')
                except Exception as e:
                    logger.error(f'Ошибка инициализации Fernet с e2e_key: {str(e)}')
                    self.e2e_key = None
                    self.cipher = None
                    self.show_notification('Недопустимый ключ шифрования. Пожалуйста, войдите заново.')
            else:
                logger.warning(f'Сессия загружена, но e2e_key отсутствует: user_id={self.user_id}, token={self.token}')
        except Exception as e:
            logger.error(f'Ошибка загрузки сессии: {str(e)}')

    def save_session(self):
        try:
            self.settings.setValue('user_id', self.user_id)
            self.settings.setValue('token', self.token)
            self.settings.setValue('e2e_key', self.e2e_key)
            self.settings.setValue('csrf_token', self.csrf_token)
            logger.debug(f'Сессия сохранена: e2e_key={self.e2e_key}')
        except Exception as e:
            logger.error(f'Ошибка сохранения сессии: {str(e)}')

    def encrypt_e2e(self, data):
        try:
            if self.cipher:
                encrypted = self.cipher.encrypt(json.dumps(data).encode()).decode()
                logger.debug(f'Зашифровано: {data}')
                return encrypted
            logger.warning('Шифрование не выполнено: отсутствует cipher')
            return json.dumps(data)
        except Exception as e:
            logger.error(f'Ошибка шифрования: {str(e)}')
            return json.dumps(data)

    def decrypt_e2e(self, encrypted):
        try:
            if not isinstance(encrypted, str):
                logger.error(f'Неверный тип данных для расшифровки: {type(encrypted)}')
                return None
            if self.cipher:
                decrypted = self.cipher.decrypt(encrypted.encode()).decode()
                data = json.loads(decrypted)
                logger.debug(f'Расшифровано: {data}')
                return data
            logger.warning('Расшифровка не выполнена: отсутствует cipher')
            try:
                data = json.loads(encrypted)
                logger.debug(f'Разобрано как JSON: {data}')
                return data
            except json.JSONDecodeError:
                logger.error('Не удалось разобрать сообщение как JSON')
                return None
        except Exception as e:
            logger.error(f'Ошибка расшифровки: {str(e)}, сообщение: {encrypted}')
            return None

    def make_request(self, method, url, **kwargs):
        try:
            current_time = time.time()
            if current_time - self.last_request_time < RETRY_DELAY:
                time.sleep(RETRY_DELAY - (current_time - self.last_request_time))
            self.last_request_time = time.time()
            
            # Логирование фактического адреса сервера
            parsed_url = requests.utils.urlparse(url)
            host = parsed_url.hostname
            try:
                ip = socket.gethostbyname(host)
                logger.debug(f"Разрешенный IP для {host}: {ip}")
            except socket.gaierror as e:
                logger.error(f"Ошибка разрешения DNS для {host}: {str(e)}")

            for attempt in range(MAX_RETRIES):
                try:
                    kwargs['verify'] = not DISABLE_SSL_VERIFY
                    headers = kwargs.get('headers', {})
                    headers['Authorization'] = f'Bearer {self.token}'
                    kwargs['headers'] = headers
                    response = requests.request(method, url, timeout=REQUEST_TIMEOUT, **kwargs)
                    response.raise_for_status()
                    logger.debug(f"Успешный запрос {method} {url}: {response.status_code}")
                    return response
                except requests.exceptions.SSLError as ssl_err:
                    logger.error(f'SSL ошибка при запросе {url}: {ssl_err}')
                    if attempt < MAX_RETRIES - 1:
                        logger.debug(f'Повторная попытка {attempt + 1}/{MAX_RETRIES} через {RETRY_DELAY} секунд')
                        time.sleep(RETRY_DELAY)
                    else:
                        raise
                except requests.exceptions.ConnectionError as conn_err:
                    logger.error(f'Ошибка соединения {url}: {conn_err}')
                    if attempt < MAX_RETRIES - 1:
                        logger.debug(f'Повторная попытка {attempt + 1}/{MAX_RETRIES} через {RETRY_DELAY} секунд')
                        time.sleep(RETRY_DELAY)
                    else:
                        raise
                except requests.exceptions.HTTPError as http_err:
                    if response.status_code == 401:
                        logger.error(f'401 Unauthorized при запросе {url}, обновляем токен')
                        self.show_notification('Токен недействителен, требуется повторный вход')
                        QTimer.singleShot(0, self.logout)
                        raise
                    logger.error(f'HTTP ошибка {url}: {http_err}')
                    if attempt < MAX_RETRIES - 1:
                        logger.debug(f'Повторная попытка {attempt + 1}/{MAX_RETRIES} через {RETRY_DELAY} секунд')
                        time.sleep(RETRY_DELAY)
                    else:
                        raise
                except requests.exceptions.RequestException as e:
                    logger.error(f'Ошибка запроса {url}: {str(e)}')
                    if attempt < MAX_RETRIES - 1:
                        logger.debug(f'Повторная попытка {attempt + 1}/{MAX_RETRIES} через {RETRY_DELAY} секунд')
                        time.sleep(RETRY_DELAY)
                    else:
                        raise
            raise Exception("Превышено максимальное количество попыток")
        except Exception as e:
            logger.error(f'Ошибка запроса {url}: {str(e)}')
            raise

    def register(self):
        try:
            phone = self.register_phone.text()
            name = self.register_name.text()
            nickname = self.register_nickname.text()
            password = self.register_password.text()
            confirm_password = self.register_confirm_password.text()
            
            if not phone or not name or not nickname or not password:
                self.show_notification('Все поля обязательны для заполнения')
                return
            if password != confirm_password:
                self.show_notification('Пароли не совпадают')
                return
            
            response = self.make_request('POST', f'{BASE_URL}/register', json={
                'phone': phone,
                'name': name,
                'nickname': nickname,
                'password': password
            })
            result = response.json()
            self.log(f'Register response: {result}')
            if response.status_code == 200:
                self.user_id = result.get('unique_id')
                self.e2e_key = result.get('e2e_key')
                if not self.e2e_key:
                    logger.error('Сервер не вернул e2e_key при регистрации')
                    self.show_notification('Ошибка: сервер не предоставил ключ шифрования')
                    return
                try:
                    self.cipher = Fernet(self.e2e_key.encode())
                except Exception as e:
                    logger.error(f'Ошибка инициализации Fernet с e2e_key: {str(e)}')
                    self.show_notification('Недопустимый ключ шифрования. Пожалуйста, зарегистрируйтесь заново.')
                    return
                self.save_session()
                self.show_notification(f'Регистрация успешна! Ваш ID: {self.user_id}')
                self.login(identifier=phone, password=password)
            else:
                self.show_notification(result.get('detail', 'Ошибка регистрации'))
        except Exception as e:
            logger.error(f'Register error: {str(e)}')
            self.show_notification(f'Ошибка регистрации: {str(e)}')

    def generate_otp(self):
        try:
            identifier = self.login_identifier.text()
            password = self.login_password.text()
            if not identifier or not password:
                self.show_notification('Введите идентификатор и пароль')
                return
            response = self.make_request('POST', f'{BASE_URL}/generate_otp', json={
                'identifier': identifier,
                'password': password
            })
            result = response.json()
            self.log(f'Generate OTP response: {result}')
            if response.status_code == 200:
                self.otp_input.setVisible(True)
                self.show_notification('Код отправлен (проверьте логи сервера)')
            else:
                self.show_notification(result.get('detail', 'Ошибка генерации OTP'))
        except Exception as e:
            logger.error(f'Generate OTP error: {str(e)}')
            self.show_notification(f'Ошибка генерации OTP: {str(e)}')

    def login(self, identifier=None, password=None):
        try:
            identifier = identifier or self.login_identifier.text()
            password = password or self.login_password.text()
            otp = self.otp_input.text() or None
            if not identifier or not password:
                self.show_notification('Введите идентификатор и пароль')
                return
            response = self.make_request('POST', f'{BASE_URL}/login', json={
                'identifier': identifier,
                'password': password,
                'otp': otp
            })
            result = response.json()
            self.log(f'Login response: {result}')
            if response.status_code == 200:
                self.token = result.get('access_token')
                self.user_id = identifier
                self.csrf_token = result.get('csrf_token')
                self.e2e_key = result.get('e2e_key')
                if not self.e2e_key:
                    logger.error('Сервер не вернул e2e_key при входе')
                    self.show_notification('Ошибка: сервер не предоставил ключ шифрования')
                    return
                try:
                    self.cipher = Fernet(self.e2e_key.encode())
                except Exception as e:
                    logger.error(f'Ошибка инициализации Fernet с e2e_key: {str(e)}')
                    self.show_notification('Недопустимый ключ шифрования. Пожалуйста, войдите заново.')
                    return
                self.save_session()
                QTimer.singleShot(0, lambda: self.user_label.setText(f'ID: {self.user_id}'))
                self.show_main_ui()
                QTimer.singleShot(100, self.connect_websocket)
                QTimer.singleShot(200, self.load_contacts)
            else:
                self.show_notification(result.get('detail', 'Ошибка входа'))
        except Exception as e:
            logger.error(f'Login error: {str(e)}')
            self.show_notification(f'Ошибка входа: {str(e)}')

    def logout(self):
        try:
            self.token = None
            self.user_id = None
            self.e2e_key = None
            self.csrf_token = None
            self.cipher = None
            if self.ws:
                self.ws.close()
                self.ws = None
            self.settings.clear()
            self.show_auth_ui()
            self.log('Logged out')
        except Exception as e:
            logger.error(f'Logout error: {str(e)}')
            self.show_notification(f'Ошибка выхода: {str(e)}')

    def load_contacts(self):
        try:
            if not self.token or not self.is_token_valid():
                logger.warning("Токен отсутствует или недействителен, пропускаем загрузку контактов")
                self.show_notification("Требуется авторизация для загрузки контактов")
                QTimer.singleShot(0, self.logout)
                return
            response = self.make_request('GET', f'{BASE_URL}/contacts')
            result = response.json()
            self.log(f'Load contacts response: {result}')
            if response.status_code == 200:
                self.contacts = result.get('contacts', [])
                QTimer.singleShot(0, self.update_contacts_list)
            else:
                self.show_notification(result.get('detail', 'Ошибка загрузки контактов'))
        except Exception as e:
            logger.error(f'Load contacts error: {str(e)}')
            self.show_notification(f'Ошибка загрузки контактов: {str(e)}')

    def update_contacts_list(self):
        try:
            self.contacts_list.clear()
            if self.contacts:
                for contact in self.contacts:
                    item = QListWidgetItem(f'ID: {contact}')
                    item.setData(Qt.UserRole, contact)
                    self.contacts_list.addItem(item)
            else:
                self.contacts_list.addItem('У вас пока нет контактов')
            logger.debug(f'Контакты обновлены: {self.contacts}')
            QApplication.processEvents()
        except Exception as e:
            logger.error(f'Update contacts list error: {str(e)}')
            self.show_notification(f'Ошибка обновления контактов: {str(e)}')

    def search_contacts(self, text):
        try:
            self.contacts_list.clear()
            for contact in self.contacts:
                if text.lower() in contact.lower():
                    item = QListWidgetItem(f'ID: {contact}')
                    item.setData(Qt.UserRole, contact)
                    self.contacts_list.addItem(item)
            if not self.contacts_list.count():
                self.contacts_list.addItem('Нет контактов по запросу')
            logger.debug(f'Поиск контактов: {text}')
            QApplication.processEvents()
        except Exception as e:
            logger.error(f'Search contacts error: {str(e)}')
            self.show_notification(f'Ошибка поиска контактов: {str(e)}')

    def show_add_contact_dialog(self):
        try:
            target_id, ok = QInputDialog.getText(self, 'Добавить контакт', 'Введите ID:')
            if ok and target_id:
                secret, ok = QInputDialog.getItem(self, 'Добавить контакт', 'Секретная подписка?', ['Нет', 'Да'], 0, False)
                self.subscribe(target_id, secret == 'Да')
        except Exception as e:
            logger.error(f'Add contact dialog error: {str(e)}')
            self.show_notification(f'Ошибка добавления контакта: {str(e)}')

    def subscribe(self, target_id, secret):
        try:
            response = self.make_request('POST', f'{BASE_URL}/subscribe', json={
                'target_id': target_id,
                'secret': secret,
                'csrf_token': self.csrf_token or ''
            })
            result = response.json()
            self.log(f'Subscribe response: {result}')
            if response.status_code == 200:
                self.show_notification('Запрос на подписку отправлен')
            else:
                self.show_notification(result.get('detail', 'Ошибка подписки'))
        except Exception as e:
            logger.error(f'Subscribe error: {str(e)}')
            self.show_notification(f'Ошибка подписки: {str(e)}')

    def confirm_subscription(self, target_id):
        try:
            response = self.make_request('POST', f'{BASE_URL}/confirm_subscribe', json={
                'target_id': target_id,
                'csrf_token': self.csrf_token or ''
            })
            result = response.json()
            self.log(f'Confirm subscription response: {result}')
            if response.status_code == 200:
                self.show_notification('Подписка подтверждена')
                self.pending_contacts = [c for c in self.pending_contacts if c['id'] != target_id]
                QTimer.singleShot(0, self.update_pending_list)
                self.load_contacts()
            else:
                self.show_notification(result.get('detail', 'Ошибка подтверждения'))
        except Exception as e:
            logger.error(f'Confirm subscription error: {str(e)}')
            self.show_notification(f'Ошибка подтверждения подписки: {str(e)}')

    def reject_subscription(self, target_id):
        try:
            self.pending_contacts = [c for c in self.pending_contacts if c['id'] != target_id]
            QTimer.singleShot(0, self.update_pending_list)
            self.show_notification('Запрос отклонен')
            logger.debug(f'Запрос на подписку отклонен: {target_id}')
        except Exception as e:
            logger.error(f'Reject subscription error: {str(e)}')
            self.show_notification(f'Ошибка отклонения подписки: {str(e)}')

    def update_pending_list(self):
        try:
            self.pending_list.clear()
            self.no_pending_label.setVisible(not bool(self.pending_contacts))
            for contact in self.pending_contacts:
                item = QListWidgetItem(f'ID: {contact["id"]} ({contact["phone"]}) {"секретная" if contact["secret"] else ""}')
                item.setData(Qt.UserRole, contact['id'])
                self.pending_list.addItem(item)
            self.pending_list.itemDoubleClicked.connect(self.handle_pending_click)
            logger.debug(f'Ожидающие подписки обновлены: {self.pending_contacts}')
            QApplication.processEvents()
        except Exception as e:
            logger.error(f'Update pending list error: {str(e)}')
            self.show_notification(f'Ошибка обновления списка ожидающих: {str(e)}')

    def handle_pending_click(self, item):
        try:
            target_id = item.data(Qt.UserRole)
            reply = QMessageBox.question(self, 'Подписка', f'Подтвердить подписку от ID {target_id}?', 
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.confirm_subscription(target_id)
            else:
                self.reject_subscription(target_id)
        except Exception as e:
            logger.error(f'Handle pending click error: {str(e)}')
            self.show_notification(f'Ошибка обработки подписки: {str(e)}')

    def check_port(self, host, port):
        """Проверяет доступность порта."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.error(f"Ошибка проверки порта {host}:{port}: {str(e)}")
            return False

    def connect_websocket(self):
        if not self.token or not self.e2e_key or not self.is_token_valid():
            self.log('No token, e2e_key, or token invalid for WebSocket connection')
            return
        try:
            # Проверка доступности порта
            parsed_url = requests.utils.urlparse(WS_URL)
            host = parsed_url.hostname
            port = parsed_url.port or 443
            if not self.check_port(host, port):
                logger.error(f"Порт {host}:{port} недоступен")
                self.show_notification(f"Сервер WebSocket недоступен ({host}:{port})")
                delay = min(WS_RECONNECT_BASE_DELAY * (2 ** self.ws_reconnect_attempts) + random.uniform(0, 1), WS_RECONNECT_MAX_DELAY)
                logger.debug(f'Планируем переподключение через {delay:.2f} секунд')
                QTimer.singleShot(int(delay * 1000), self.connect_websocket)
                self.ws_reconnect_attempts += 1
                return

            self.ws = websocket.WebSocketApp(
                f'{WS_URL}?token={self.token}',
                on_open=self.on_ws_open,
                on_message=self.on_ws_message,
                on_error=self.on_ws_error,
                on_close=self.on_ws_close
            )
            threading.Thread(target=self.ws.run_forever, kwargs={
                'sslopt': {'cert_reqs': ssl.CERT_NONE},
                'ping_interval': 30,
                'ping_timeout': 25
            }, daemon=True).start()
            logger.debug(f'WebSocket thread started (попытка {self.ws_reconnect_attempts + 1})')
            self.ws_reconnect_attempts += 1
        except Exception as e:
            logger.error(f'WebSocket connection error (попытка {self.ws_reconnect_attempts + 1}): {str(e)}')
            delay = min(WS_RECONNECT_BASE_DELAY * (2 ** self.ws_reconnect_attempts) + random.uniform(0, 1), WS_RECONNECT_MAX_DELAY)
            logger.debug(f'Планируем переподключение через {delay:.2f} секунд')
            QTimer.singleShot(int(delay * 1000), self.connect_websocket)
            self.ws_reconnect_attempts += 1

    def send_ws_message(self, data):
        try:
            if self.ws and self.ws.sock and self.ws.sock.connected:
                encrypted = self.encrypt_e2e(data)
                self.ws.send(encrypted)
                self.log(f'WebSocket sent: {data}')
            else:
                logger.warning('WebSocket не подключен или отсутствует cipher')
                self.show_notification('WebSocket не подключен, попробуйте позже')
        except Exception as e:
            logger.error(f'WebSocket send error: {str(e)}')
            self.show_notification(f'Ошибка отправки WebSocket: {str(e)}')

    def on_ws_open(self, ws):
        def run():
            self.ws_reconnect_attempts = 0
            self.log('WebSocket подключен')
            self.show_notification('Подключено к серверу')
        QTimer.singleShot(0, run)

    def on_ws_message(self, ws, message):
        try:
            logger.debug(f'Получено WebSocket-сообщение: {message}')
            data = self.decrypt_e2e(message)
            if not data:
                logger.warning('Не удалось расшифровать сообщение')
                return
            self.log(f'WebSocket message: {data}')
            if not isinstance(data, dict) or 'type' not in data:
                logger.error(f'Неверный формат сообщения: {data}')
                return
            if data['type'] == 'subscription_request':
                if 'from_id' not in data or 'from_phone' not in data:
                    logger.error(f'Неполные данные в subscription_request: {data}')
                    return
                def handle_subscription():
                    self.pending_contacts.append({
                        'id': data['from_id'],
                        'phone': data['from_phone'],
                        'secret': data.get('secret', False)
                    })
                    QTimer.singleShot(0, self.update_pending_list)
                    self.show_notification(f'Новый запрос на подписку от {data["from_phone"]} (ID: {data["from_id"]})')
                QTimer.singleShot(0, handle_subscription)
            elif data['type'] == 'subscription_confirmed':
                if 'from_id' not in data or 'from_phone' not in data:
                    logger.error(f'Неполные данные в subscription_confirmed: {data}')
                    return
                def handle_confirmed():
                    self.show_notification(f'Подписка подтверждена от {data["from_phone"]} (ID: {data["from_id"]})')
                    self.load_contacts()
                QTimer.singleShot(0, handle_confirmed)
            elif data['type'] == 'offer':
                if 'from_id' not in data or 'from_phone' not in data:
                    logger.error(f'Неполные данные в offer: {data}')
                    return
                def handle_offer():
                    reply = QMessageBox.question(self, 'Входящий вызов', 
                                                f'Входящий вызов от {data["from_phone"]} (ID: {data["from_id"]})', 
                                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                    if reply == QMessageBox.Yes:
                        self.accept_call(data['from_id'])
                    else:
                        self.reject_call(data['from_id'])
                QTimer.singleShot(0, handle_offer)
            else:
                logger.warning(f'Неизвестный тип сообщения: {data["type"]}')
        except Exception as e:
            logger.error(f'WebSocket message error: {str(e)}')
            self.show_notification(f'Ошибка обработки сообщения WebSocket: {str(e)}')

    def on_ws_error(self, ws, error):
        def run():
            self.log(f'WebSocket error: {error}')
            self.show_notification('Ошибка соединения с сервером')
        QTimer.singleShot(0, run)

    def on_ws_close(self, ws, code, reason):
        def run():
            self.log(f'WebSocket закрыт: {code}, {reason}')
            self.show_notification('Отключено от сервера, переподключение...')
            delay = min(WS_RECONNECT_BASE_DELAY * (2 ** self.ws_reconnect_attempts) + random.uniform(0, 1), WS_RECONNECT_MAX_DELAY)
            logger.debug(f'Планируем переподключение через {delay:.2f} секунд')
            QTimer.singleShot(int(delay * 1000), self.connect_websocket)
            self.ws_reconnect_attempts += 1
        QTimer.singleShot(0, run)

    def accept_call(self, from_id):
        try:
            if self.ws:
                message = {'type': 'call_accept', 'target': from_id}
                self.send_ws_message(message)
                self.start_call(from_id)
        except Exception as e:
            logger.error(f'Accept call error: {str(e)}')
            self.show_notification(f'Ошибка принятия вызова: {str(e)}')

    def reject_call(self, from_id):
        try:
            if self.ws:
                message = {'type': 'call_reject', 'target': from_id}
                self.send_ws_message(message)
            self.show_notification('Вызов отклонен')
        except Exception as e:
            logger.error(f'Reject call error: {str(e)}')
            self.show_notification(f'Ошибка отклонения вызова: {str(e)}')

    def start_call(self, target_id):
        try:
            self.current_call_id = target_id
            QTimer.singleShot(0, lambda: self.call_status.setText(f'Вызов с ID: {target_id}'))
            QTimer.singleShot(0, lambda: self.call_user.setText('Соединение установлено'))
            QTimer.singleShot(0, lambda: self.end_call_btn.setVisible(True))
            QApplication.processEvents()
        except Exception as e:
            logger.error(f'Start call error: {str(e)}')
            self.show_notification(f'Ошибка начала вызова: {str(e)}')

    def start_call_from_list(self, item):
        try:
            target_id = item.data(Qt.UserRole)
            if target_id:
                self.send_ws_message({'type': 'offer', 'target': target_id, 'sdp': 'test_sdp_data'})
                self.start_call(target_id)
                self.show_notification(f'Вызов отправлен ID: {target_id}')
        except Exception as e:
            logger.error(f'Start call from list error: {str(e)}')
            self.show_notification(f'Ошибка начала вызова: {str(e)}')

    def end_call(self):
        try:
            if self.current_call_id and self.ws:
                message = {'type': 'call_reject', 'target': self.current_call_id}
                self.send_ws_message(message)
            self.current_call_id = None
            QTimer.singleShot(0, lambda: self.call_status.setText('Выберите контакт для звонка'))
            QTimer.singleShot(0, lambda: self.call_user.setText(''))
            QTimer.singleShot(0, lambda: self.end_call_btn.setVisible(False))
            QApplication.processEvents()
        except Exception as e:
            logger.error(f'End call error: {str(e)}')
            self.show_notification(f'Ошибка завершения вызова: {str(e)}')

if __name__ == '__main__':
    try:
        logger.debug("Запуск приложения")
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        client = MeloVoiceClient()
        client.show()
        client.raise_()
        client.repaint()
        logger.debug("Окно приложения отображено")
        sys.exit(app.exec_())
    except Exception as e:
        logger.error(f'Критическая ошибка приложения: {str(e)}')
        raise
