"""
Модуль аутентификации пользователя по мастер-паролю.

Мастер-пароль хранится только в виде SHA-256 хеша в data/master.hash.
Реализована защита от перебора: блокировка на 30 секунд после 3 неудачных попыток.
"""

import hashlib
import os
import time
from typing import Optional, Tuple

from logger import app_logger

# Путь к файлу хеша мастер-пароля
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
MASTER_HASH_FILE = os.path.join(DATA_DIR, "master.hash")

# Параметры защиты от перебора
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_SECONDS = 30


class AuthManager:
    """Управление аутентификацией и защитой от перебора пароля."""

    def __init__(self) -> None:
        """Инициализация менеджера аутентификации."""
        self._failed_attempts = 0
        self._lockout_until: float = 0.0
        self._ensure_data_dir()

    def _ensure_data_dir(self) -> None:
        """Создаёт директорию data при необходимости."""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
        except OSError as error:
            app_logger.log_error(f"Не удалось создать директорию data: {error}")

    @staticmethod
    def _hash_password(password: str) -> str:
        """
        Вычисляет SHA-256 хеш пароля.

        :param password: мастер-пароль в открытом виде (только в памяти)
        :return: hex-строка хеша
        """
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def is_first_run(self) -> bool:
        """Проверяет, был ли уже создан мастер-пароль."""
        return not os.path.exists(MASTER_HASH_FILE)

    def create_master_password(self, password: str) -> Tuple[bool, str]:
        """
        Создаёт мастер-пароль при первом запуске.

        :param password: новый мастер-пароль
        :return: (успех, сообщение для пользователя)
        """
        if not password or len(password) < 4:
            return False, "Мастер-пароль должен содержать не менее 4 символов."

        try:
            password_hash = self._hash_password(password)
            with open(MASTER_HASH_FILE, "w", encoding="utf-8") as hash_file:
                hash_file.write(password_hash)
            app_logger.log(
                app_logger.EVENT_DIAGNOSTIC,
                "Создан файл master.hash (мастер-пароль установлен)",
            )
            return True, "Мастер-пароль успешно создан."
        except OSError as error:
            app_logger.log_error(f"Ошибка сохранения master.hash: {error}")
            return False, "Не удалось сохранить мастер-пароль."

    def ensure_master_hash_file(self) -> None:
        """Самодиагностика: файл master.hash создаётся только при первом входе."""
        self._ensure_data_dir()

    def get_lockout_remaining(self) -> int:
        """
        Возвращает оставшееся время блокировки в секундах.

        :return: секунды до разблокировки или 0
        """
        remaining = int(self._lockout_until - time.time())
        return max(0, remaining)

    def is_locked_out(self) -> bool:
        """Проверяет, активна ли блокировка после неудачных попыток."""
        if self.get_lockout_remaining() > 0:
            return True
        if self._lockout_until > 0 and time.time() >= self._lockout_until:
            self._failed_attempts = 0
            self._lockout_until = 0.0
        return False

    def verify_password(self, password: str) -> Tuple[bool, str]:
        """
        Проверяет введённый мастер-пароль.

        :param password: пароль для проверки
        :return: (успех, сообщение)
        """
        if self.is_locked_out():
            remaining = self.get_lockout_remaining()
            return False, f"Доступ заблокирован. Повторите через {remaining} сек."

        try:
            if not os.path.exists(MASTER_HASH_FILE):
                return False, "Мастер-пароль не настроен. Перезапустите приложение."

            with open(MASTER_HASH_FILE, "r", encoding="utf-8") as hash_file:
                stored_hash = hash_file.read().strip()

            if not stored_hash:
                app_logger.log_error("Файл master.hash повреждён (пустой)")
                return False, "Файл master.hash повреждён."

            input_hash = self._hash_password(password)

            if input_hash == stored_hash:
                self._failed_attempts = 0
                self._lockout_until = 0.0
                app_logger.log(app_logger.EVENT_LOGIN_SUCCESS, "Успешный вход в систему")
                return True, "Вход выполнен успешно."

            self._failed_attempts += 1
            app_logger.log(
                app_logger.EVENT_LOGIN_FAIL,
                f"Неудачная попытка входа ({self._failed_attempts}/{MAX_FAILED_ATTEMPTS})",
            )

            if self._failed_attempts >= MAX_FAILED_ATTEMPTS:
                self._lockout_until = time.time() + LOCKOUT_SECONDS
                app_logger.log(
                    app_logger.EVENT_LOCKOUT,
                    f"Доступ заблокирован на {LOCKOUT_SECONDS} секунд после "
                    f"{MAX_FAILED_ATTEMPTS} неудачных попыток",
                )
                return (
                    False,
                    f"Превышено число попыток. Доступ заблокирован на {LOCKOUT_SECONDS} сек.",
                )

            attempts_left = MAX_FAILED_ATTEMPTS - self._failed_attempts
            return False, f"Неверный пароль. Осталось попыток: {attempts_left}."

        except OSError as error:
            app_logger.log_error(f"Ошибка чтения master.hash: {error}")
            return False, "Ошибка проверки пароля."

    def reset_lockout(self) -> None:
        """Сбрасывает счётчик неудачных попыток (после автоблокировки)."""
        self._failed_attempts = 0
        self._lockout_until = 0.0


# Глобальный экземпляр менеджера аутентификации
auth_manager = AuthManager()
