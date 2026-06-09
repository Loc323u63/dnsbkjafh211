"""
Модуль шифрования данных с использованием Fernet (cryptography).

Ключ шифрования хранится в data/key.key и создаётся автоматически при первом запуске.
"""

import os
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

from logger import app_logger

# Директория и путь к файлу ключа
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
KEY_FILE = os.path.join(DATA_DIR, "key.key")


class EncryptionManager:
    """Управление ключом шифрования и операциями Fernet."""

    def __init__(self) -> None:
        """Инициализация менеджера шифрования."""
        self._fernet: Optional[Fernet] = None
        self._ensure_data_dir()

    def _ensure_data_dir(self) -> None:
        """Создаёт директорию data, если она отсутствует."""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except OSError as error:
            app_logger.log_error(f"Не удалось создать директорию data: {error}")

    def ensure_key_file(self) -> bool:
        """
        Проверяет наличие key.key и создаёт новый ключ при необходимости.

        :return: True при успехе, False при ошибке
        """
        try:
            self._ensure_data_dir()
            if not os.path.exists(KEY_FILE):
                key = Fernet.generate_key()
                with open(KEY_FILE, "wb") as key_file:
                    key_file.write(key)
                app_logger.log(
                    app_logger.EVENT_DIAGNOSTIC,
                    "Создан новый файл ключа шифрования key.key",
                )
            return self.load_key()
        except OSError as error:
            app_logger.log_error(f"Ошибка создания key.key: {error}")
            return False

    def load_key(self) -> bool:
        """
        Загружает ключ шифрования из файла.

        :return: True при успешной загрузке
        """
        try:
            if not os.path.exists(KEY_FILE):
                return False
            with open(KEY_FILE, "rb") as key_file:
                key = key_file.read()
            self._fernet = Fernet(key)
            return True
        except (OSError, ValueError) as error:
            app_logger.log_error(f"Ошибка загрузки ключа шифрования: {error}")
            self._fernet = None
            return False

    def encrypt(self, plaintext: str) -> Optional[str]:
        """
        Шифрует строку и возвращает токен в виде строки UTF-8.

        :param plaintext: исходный текст
        :return: зашифрованная строка или None при ошибке
        """
        if self._fernet is None:
            if not self.load_key():
                return None
        try:
            token = self._fernet.encrypt(plaintext.encode("utf-8"))
            return token.decode("utf-8")
        except Exception as error:
            app_logger.log_error(f"Ошибка шифрования: {error}")
            return None

    def decrypt(self, token_str: str) -> Optional[str]:
        """
        Расшифровывает строку-токен Fernet.

        :param token_str: зашифрованная строка
        :return: расшифрованный текст или None при ошибке
        """
        if self._fernet is None:
            if not self.load_key():
                return None
        try:
            plaintext = self._fernet.decrypt(token_str.encode("utf-8"))
            return plaintext.decode("utf-8")
        except InvalidToken:
            app_logger.log_error("Ошибка расшифровки: повреждённый или неверный токен")
            return None
        except Exception as error:
            app_logger.log_error(f"Ошибка расшифровки: {error}")
            return None

    def is_key_valid(self) -> bool:
        """Проверяет, что ключ загружен и может использоваться."""
        if self._fernet is None:
            return self.load_key()
        return True


# Глобальный экземпляр менеджера шифрования
encryption_manager = EncryptionManager()
