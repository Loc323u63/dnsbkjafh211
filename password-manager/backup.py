"""
Модуль резервного копирования и восстановления данных passwords.json.
"""

import os
import shutil
from datetime import datetime
from typing import Optional, Tuple

from logger import app_logger

# Директории проекта
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_DIR, "data")
BACKUP_DIR = os.path.join(PROJECT_DIR, "backups")
PASSWORDS_FILE = os.path.join(DATA_DIR, "passwords.json")


class BackupManager:
    """Создание и восстановление резервных копий зашифрованного хранилища."""

    def __init__(self) -> None:
        """Инициализация менеджера резервного копирования."""
        self._ensure_backup_dir()

    def _ensure_backup_dir(self) -> None:
        """Создаёт папку backups при необходимости."""
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
        except OSError as error:
            app_logger.log_error(f"Не удалось создать папку backups: {error}")

    def create_backup(self) -> Tuple[bool, str]:
        """
        Создаёт резервную копию passwords.json с меткой даты и времени.

        :return: (успех, путь к копии или сообщение об ошибке)
        """
        try:
            self._ensure_backup_dir()

            if not os.path.exists(PASSWORDS_FILE):
                return False, "Файл passwords.json не найден. Нечего копировать."

            timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
            backup_name = f"backup_{timestamp}.json"
            backup_path = os.path.join(BACKUP_DIR, backup_name)

            shutil.copy2(PASSWORDS_FILE, backup_path)

            app_logger.log(
                app_logger.EVENT_BACKUP,
                f"Создана резервная копия: {backup_name}",
            )
            return True, backup_path

        except OSError as error:
            app_logger.log_error(f"Ошибка создания резервной копии: {error}")
            return False, f"Ошибка создания резервной копии: {error}"

    def restore_backup(self, backup_path: str) -> Tuple[bool, str]:
        """
        Восстанавливает passwords.json из выбранного backup-файла.

        :param backup_path: путь к файлу резервной копии
        :return: (успех, сообщение)
        """
        try:
            if not os.path.exists(backup_path):
                return False, "Файл резервной копии не найден."

            os.makedirs(DATA_DIR, exist_ok=True)
            shutil.copy2(backup_path, PASSWORDS_FILE)

            app_logger.log(
                app_logger.EVENT_RESTORE,
                f"Данные восстановлены из: {os.path.basename(backup_path)}",
            )
            return True, "Данные успешно восстановлены из резервной копии."

        except OSError as error:
            app_logger.log_error(f"Ошибка восстановления из резервной копии: {error}")
            return False, f"Ошибка восстановления: {error}"

    def list_backups(self) -> list[str]:
        """Возвращает список файлов резервных копий."""
        try:
            self._ensure_backup_dir()
            files = [
                os.path.join(BACKUP_DIR, name)
                for name in os.listdir(BACKUP_DIR)
                if name.startswith("backup_") and name.endswith(".json")
            ]
            return sorted(files, reverse=True)
        except OSError:
            return []


backup_manager = BackupManager()
