"""
Вспомогательные функции: генератор паролей, анализ надёжности, самодиагностика, QR-коды.
"""

import json
import os
import random
import re
import string
from datetime import datetime
from typing import Any, Optional, Tuple

from logger import app_logger

# Специальные символы для генератора паролей
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


def generate_password(
    length: int = 16,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
) -> str:
    """
    Генерирует надёжный пароль заданной длины.

    :param length: длина пароля (12–20)
    :param use_lower: использовать строчные буквы
    :param use_upper: использовать заглавные буквы
    :param use_digits: использовать цифры
    :param use_special: использовать спецсимволы
    :return: сгенерированный пароль
    """
    length = max(12, min(20, length))
    charset = ""
    required_chars: list[str] = []

    if use_lower:
        charset += string.ascii_lowercase
        required_chars.append(random.choice(string.ascii_lowercase))
    if use_upper:
        charset += string.ascii_uppercase
        required_chars.append(random.choice(string.ascii_uppercase))
    if use_digits:
        charset += string.digits
        required_chars.append(random.choice(string.digits))
    if use_special:
        charset += SPECIAL_CHARS
        required_chars.append(random.choice(SPECIAL_CHARS))

    if not charset:
        charset = string.ascii_letters + string.digits + SPECIAL_CHARS
        required_chars = [random.choice(charset) for _ in range(4)]

    password_chars = required_chars[:]
    while len(password_chars) < length:
        password_chars.append(random.choice(charset))

    random.shuffle(password_chars)
    return "".join(password_chars[:length])


def analyze_password_strength(password: str) -> Tuple[int, str, list[str]]:
    """
    Оценивает надёжность пароля по шкале 0–100.

    Учитывает длину, цифры, спецсимволы и разные регистры букв.

    :param password: пароль для анализа
    :return: (оценка 0–100, уровень «слабый/средний/сильный», список рекомендаций)
    """
    score = 0
    recommendations: list[str] = []

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password))

    # Оценка по длине (до 40 баллов)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        score += 10
        recommendations.append("Увеличьте длину пароля (рекомендуется от 12 символов).")

    # Баллы за разнообразие символов
    if has_lower:
        score += 10
    else:
        recommendations.append("Добавьте строчные буквы.")

    if has_upper:
        score += 10
    else:
        recommendations.append("Используйте буквы разных регистров (заглавные).")

    if has_digit:
        score += 20
    else:
        recommendations.append("Добавьте цифры.")

    if has_special:
        score += 20
    else:
        recommendations.append("Добавьте специальные символы (!@#$% и т.д.).")

    score = min(100, score)

    if score < 40:
        level = "слабый"
    elif score < 70:
        level = "средний"
    else:
        level = "сильный"
        recommendations = []

    return score, level, recommendations


def compute_statistics(records: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Вычисляет статистику по сохранённым записям паролей.

    :param records: список записей с полем password
    :return: словарь со статистикой
    """
    total = len(records)
    if total == 0:
        return {
            "total": 0,
            "avg_length": 0.0,
            "strong_count": 0,
            "strong_percent": 0.0,
        }

    lengths: list[int] = []
    strong_count = 0

    for record in records:
        password = record.get("password", "")
        lengths.append(len(password))
        score, level, _ = analyze_password_strength(password)
        if level == "сильный":
            strong_count += 1

    avg_length = sum(lengths) / len(lengths)
    strong_percent = (strong_count / total) * 100

    return {
        "total": total,
        "avg_length": round(avg_length, 1),
        "strong_count": strong_count,
        "strong_percent": round(strong_percent, 1),
    }


def run_self_diagnostics(
    passwords_file: str,
    master_hash_file: str,
    key_file: str,
    log_file: str,
) -> list[str]:
    """
    Самодиагностика при запуске: проверка и создание необходимых файлов.

    :return: список предупреждений для показа пользователю
    """
    warnings: list[str] = []

    # Создание директорий
    for directory in [
        os.path.dirname(passwords_file),
        os.path.dirname(log_file),
        os.path.join(os.path.dirname(passwords_file), "..", "backups"),
        os.path.join(os.path.dirname(passwords_file), "..", "exports"),
    ]:
        try:
            os.makedirs(os.path.abspath(directory), exist_ok=True)
        except OSError as error:
            msg = f"Не удалось создать директорию {directory}: {error}"
            warnings.append(msg)
            app_logger.log_error(msg)

    # passwords.json — создаём пустой зашифрованный контейнер позже через PasswordManager
    if not os.path.exists(passwords_file):
        app_logger.log(
            app_logger.EVENT_DIAGNOSTIC,
            "Файл passwords.json отсутствует — будет создан при первом сохранении",
        )

    # master.hash — создаётся при первом входе
    if not os.path.exists(master_hash_file):
        app_logger.log(
            app_logger.EVENT_DIAGNOSTIC,
            "Файл master.hash отсутствует — требуется первичная настройка",
        )

    # key.key
    if not os.path.exists(key_file):
        app_logger.log(
            app_logger.EVENT_DIAGNOSTIC,
            "Файл key.key отсутствует — будет создан автоматически",
        )

    # logs.txt
    if not os.path.exists(log_file):
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("")
            app_logger.log(app_logger.EVENT_DIAGNOSTIC, "Создан файл logs/logs.txt")
        except OSError as error:
            msg = f"Не удалось создать logs.txt: {error}"
            warnings.append(msg)
            app_logger.log_error(msg)

    # Проверка повреждения passwords.json (если существует)
    if os.path.exists(passwords_file):
        try:
            with open(passwords_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                json.loads(content)
        except json.JSONDecodeError:
            msg = "Файл passwords.json повреждён (некорректный JSON)."
            warnings.append(msg)
            app_logger.log_error(msg)

    return warnings


def save_qr_code(data: str, filepath: str) -> bool:
    """
    Генерирует QR-код и сохраняет как изображение PNG.

    :param data: данные для кодирования
    :param filepath: путь к файлу изображения
    :return: True при успехе
    """
    try:
        import qrcode

        qr = qrcode.QRCode(version=1, box_size=8, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        image = qr.make_image(fill_color="black", back_color="white")
        image.save(filepath)
        return True
    except Exception as error:
        app_logger.log_error(f"Ошибка генерации QR-кода: {error}")
        return False
