"""
Модуль журналирования событий приложения «Менеджер паролей».

Записывает все значимые действия пользователя и ошибки в файл logs/logs.txt.
"""

import os
from datetime import datetime
from typing import Optional

# Путь к файлу журнала относительно корня проекта
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "logs.txt")


class AppLogger:
    """Класс для централизованного логирования событий приложения."""

    # Типы событий для единообразного форматирования записей
    EVENT_START = "ЗАПУСК"
    EVENT_LOGIN_SUCCESS = "ВХОД_УСПЕХ"
    EVENT_LOGIN_FAIL = "ВХОД_ОШИБКА"
    EVENT_LOCKOUT = "БЛОКИРОВКА"
    EVENT_CREATE = "СОЗДАНИЕ"
    EVENT_UPDATE = "ИЗМЕНЕНИЕ"
    EVENT_DELETE = "УДАЛЕНИЕ"
    EVENT_GENERATE = "ГЕНЕРАЦИЯ"
    EVENT_BACKUP = "РЕЗЕРВНАЯ_КОПИЯ"
    EVENT_RESTORE = "ВОССТАНОВЛЕНИЕ"
    EVENT_EXPORT = "ЭКСПОРТ_PDF"
    EVENT_ERROR = "ОШИБКА"
    EVENT_AUTO_LOCK = "АВТОБЛОКИРОВКА"
    EVENT_DIAGNOSTIC = "ДИАГНОСТИКА"

    def __init__(self) -> None:
        """Инициализация логгера и создание директории для журнала."""
        self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        """Создаёт папку logs, если она отсутствует."""
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
        except OSError:
            pass

    def _write(self, event_type: str, description: str) -> None:
        """
        Записывает одну строку в журнал.

        Формат: [ДД.ММ.ГГГГ ЧЧ:ММ:СС] | ТИП | Описание
        """
        try:
            self._ensure_log_dir()
            timestamp = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
            line = f"[{timestamp}] | {event_type} | {description}\n"
            with open(LOG_FILE, "a", encoding="utf-8") as log_file:
                log_file.write(line)
        except OSError:
            # Если запись невозможна, приложение не должно падать
            pass

    def log(self, event_type: str, description: str) -> None:
        """Публичный метод записи события в журнал."""
        self._write(event_type, description)

    def log_error(self, description: str) -> None:
        """Записывает ошибку в журнал."""
        self._write(self.EVENT_ERROR, description)

    def get_recent_entries(self, limit: int = 50) -> list[str]:
        """
        Возвращает последние записи журнала для окна «История действий».

        :param limit: максимальное количество строк
        :return: список строк журнала (новые записи в конце)
        """
        try:
            if not os.path.exists(LOG_FILE):
                return []
            with open(LOG_FILE, "r", encoding="utf-8") as log_file:
                lines = log_file.readlines()
            return [line.rstrip("\n") for line in lines[-limit:]]
        except OSError:
            return []

    def ensure_log_file(self) -> None:
        """Создаёт пустой файл журнала, если он отсутствует (самодиагностика)."""
        try:
            self._ensure_log_dir()
            if not os.path.exists(LOG_FILE):
                with open(LOG_FILE, "w", encoding="utf-8") as log_file:
                    log_file.write("")
        except OSError:
            pass


# Глобальный экземпляр логгера для использования во всех модулях
app_logger = AppLogger()
