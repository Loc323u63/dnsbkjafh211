"""
Модуль управления записями паролей.

Все данные хранятся в зашифрованном виде в passwords.json.
Расшифровка выполняется только после успешной авторизации.
"""

import json
import os
from datetime import datetime
from typing import Any, Optional

from encryption import encryption_manager
from logger import app_logger

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
PASSWORDS_FILE = os.path.join(DATA_DIR, "passwords.json")


class PasswordManager:
    """CRUD-операции над зашифрованным хранилищем паролей."""

    def __init__(self) -> None:
        """Инициализация менеджера паролей."""
        self._records: list[dict[str, Any]] = []
        self._authenticated = False
        self._ensure_data_dir()

    def _ensure_data_dir(self) -> None:
        """Создаёт директорию data."""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except OSError as error:
            app_logger.log_error(f"Не удалось создать data: {error}")

    def set_authenticated(self, value: bool) -> None:
        """Устанавливает флаг успешной авторизации."""
        self._authenticated = value
        if not value:
            self._records = []

    def load_records(self) -> tuple[bool, str]:
        """
        Загружает и расшифровывает записи из passwords.json.

        :return: (успех, сообщение)
        """
        if not self._authenticated:
            return False, "Требуется авторизация."

        try:
            encryption_manager.ensure_key_file()

            if not os.path.exists(PASSWORDS_FILE):
                self._records = []
                return True, "Хранилище пусто."

            with open(PASSWORDS_FILE, "r", encoding="utf-8") as file:
                raw = file.read().strip()

            if not raw:
                self._records = []
                return True, "Хранилище пусто."

            container = json.loads(raw)
            encrypted_data = container.get("encrypted", "")

            if not encrypted_data:
                self._records = []
                return True, "Хранилище пусто."

            decrypted = encryption_manager.decrypt(encrypted_data)
            if decrypted is None:
                return False, "Не удалось расшифровать данные. Файл повреждён."

            self._records = json.loads(decrypted)
            return True, f"Загружено записей: {len(self._records)}."

        except json.JSONDecodeError:
            app_logger.log_error("passwords.json: повреждённый JSON")
            return False, "Файл passwords.json повреждён."
        except OSError as error:
            app_logger.log_error(f"Ошибка чтения passwords.json: {error}")
            return False, f"Ошибка чтения файла: {error}"

    def _save_records(self) -> tuple[bool, str]:
        """
        Шифрует и сохраняет записи в passwords.json.

        :return: (успех, сообщение)
        """
        if not self._authenticated:
            return False, "Требуется авторизация."

        try:
            encryption_manager.ensure_key_file()
            plaintext = json.dumps(self._records, ensure_ascii=False)
            encrypted = encryption_manager.encrypt(plaintext)

            if encrypted is None:
                return False, "Ошибка шифрования данных."

            container = {"encrypted": encrypted}
            with open(PASSWORDS_FILE, "w", encoding="utf-8") as file:
                json.dump(container, file, ensure_ascii=False, indent=2)

            return True, "Данные сохранены."

        except OSError as error:
            app_logger.log_error(f"Ошибка записи passwords.json: {error}")
            return False, f"Ошибка записи: {error}"

    def get_records(self) -> list[dict[str, Any]]:
        """Возвращает копию списка записей."""
        return list(self._records)

    def add_record(self, site: str, login: str, password: str) -> tuple[bool, str]:
        """Добавляет новую запись."""
        if not site.strip() or not login.strip() or not password:
            return False, "Заполните все поля: сайт, логин и пароль."

        record = {
            "site": site.strip(),
            "login": login.strip(),
            "password": password,
            "created_at": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        }
        self._records.append(record)

        success, message = self._save_records()
        if success:
            app_logger.log(
                app_logger.EVENT_CREATE,
                f"Создана запись для сайта: {site.strip()}",
            )
        return success, message

    def update_record(self, index: int, site: str, login: str, password: str) -> tuple[bool, str]:
        """Обновляет запись по индексу."""
        if index < 0 or index >= len(self._records):
            return False, "Запись не выбрана."

        if not site.strip() or not login.strip() or not password:
            return False, "Заполните все поля."

        old_site = self._records[index]["site"]
        self._records[index] = {
            "site": site.strip(),
            "login": login.strip(),
            "password": password,
            "created_at": self._records[index]["created_at"],
        }

        success, message = self._save_records()
        if success:
            app_logger.log(
                app_logger.EVENT_UPDATE,
                f"Изменена запись: {old_site} -> {site.strip()}",
            )
        return success, message

    def delete_record(self, index: int) -> tuple[bool, str]:
        """Удаляет запись по индексу."""
        if index < 0 or index >= len(self._records):
            return False, "Запись не выбрана."

        site = self._records[index]["site"]
        del self._records[index]

        success, message = self._save_records()
        if success:
            app_logger.log(app_logger.EVENT_DELETE, f"Удалена запись: {site}")
        return success, message

    def search_by_site(self, query: str) -> list[tuple[int, dict[str, Any]]]:
        """
        Фильтрует записи по названию сайта.

        :return: список пар (индекс в хранилище, запись)
        """
        query_lower = query.strip().lower()
        indexed = list(enumerate(self._records))
        if not query_lower:
            return indexed
        return [(i, r) for i, r in indexed if query_lower in r["site"].lower()]

    def ensure_passwords_file(self) -> None:
        """Самодиагностика: создаёт пустой зашифрованный файл при отсутствии."""
        if os.path.exists(PASSWORDS_FILE):
            return
        self._records = []
        self._authenticated = True
        self._save_records()
        self._authenticated = False


password_manager = PasswordManager()
