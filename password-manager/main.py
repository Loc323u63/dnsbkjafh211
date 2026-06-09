"""
Главный модуль приложения «Менеджер паролей».

Точка входа: авторизация, главное окно, все функции GUI.
Демонстрирует принципы программной защиты информации.
"""

import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Any, Optional

import pyperclip

from auth import auth_manager
from backup import backup_manager
from encryption import encryption_manager
from logger import app_logger, LOG_FILE
from password_manager import password_manager as pwd_manager, PASSWORDS_FILE
from utils import (
    analyze_password_strength,
    compute_statistics,
    generate_password,
    run_self_diagnostics,
    save_qr_code,
)

# Корневая директория проекта
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_DIR, "data")
EXPORTS_DIR = os.path.join(PROJECT_DIR, "exports")
MASTER_HASH_FILE = os.path.join(DATA_DIR, "master.hash")
KEY_FILE = os.path.join(DATA_DIR, "key.key")

# Интервал автоблокировки: 5 минут бездействия
AUTO_LOCK_MS = 5 * 60 * 1000

# Цветовая схема тёмной темы
COLORS = {
    "bg": "#1e1e2e",
    "fg": "#cdd6f4",
    "accent": "#89b4fa",
    "accent_hover": "#74c7ec",
    "entry_bg": "#313244",
    "button_bg": "#45475a",
    "button_fg": "#cdd6f4",
    "tree_bg": "#181825",
    "tree_fg": "#cdd6f4",
    "weak": "#f38ba8",
    "medium": "#fab387",
    "strong": "#a6e3a1",
    "header": "#cba6f7",
}


class PasswordManagerApp:
    """Главный класс приложения с графическим интерфейсом."""

    def __init__(self) -> None:
        """Инициализация приложения и запуск самодиагностики."""
        try:
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "=== НАЧАЛО ИНИЦИАЛИЗАЦИИ ПРИЛОЖЕНИЯ ===")
            
            self.root = tk.Tk()
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Tkinter корень создан")
            
            self.root.title("Менеджер паролей — Защита информации")
            self.root.geometry("900x600")
            self.root.minsize(800, 500)
            self.root.configure(bg=COLORS["bg"])
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Окно настроено (900x600)")

            self._selected_index: Optional[int] = None
            self._auto_lock_job: Optional[str] = None
            self._lockout_update_job: Optional[str] = None
            self._activity_bound = False

            self._setup_styles()
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Стили настроены")
            
            self._run_startup_diagnostics()
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Самодиагностика пройдена")

            app_logger.log(app_logger.EVENT_START, "Запуск приложения «Менеджер паролей»")
            app_logger.ensure_log_file()
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "=== ИНИЦИАЛИЗАЦИЯ ЗАВЕРШЕНА ===")
            
        except Exception as error:
            app_logger.log_error(f"КРИТИЧЕСКАЯ ОШИБКА ИНИЦИАЛИЗАЦИИ: {error}")
            app_logger.log_error(f"Тип ошибки: {type(error).__name__}")
            import traceback
            app_logger.log_error(f"Трассировка: {traceback.format_exc()}")
            raise

    def _setup_styles(self) -> None:
        """Настройка ttk-стилей для современного тёмного интерфейса."""
        try:
            style = ttk.Style()
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass

            style.configure(
                "Dark.TFrame",
                background=COLORS["bg"],
            )
            style.configure(
                "Dark.TLabel",
                background=COLORS["bg"],
                foreground=COLORS["fg"],
                font=("Segoe UI", 10),
            )
            style.configure(
                "Header.TLabel",
                background=COLORS["bg"],
                foreground=COLORS["header"],
                font=("Segoe UI", 14, "bold"),
            )
            style.configure(
                "Dark.TButton",
                background=COLORS["button_bg"],
                foreground=COLORS["button_fg"],
                font=("Segoe UI", 9),
                padding=6,
            )
            style.map(
                "Dark.TButton",
                background=[("active", COLORS["accent"])],
                foreground=[("active", "#1e1e2e")],
            )
            style.configure(
                "Dark.TEntry",
                fieldbackground=COLORS["entry_bg"],
                foreground=COLORS["fg"],
                insertcolor=COLORS["fg"],
            )
            style.configure(
                "Dark.Treeview",
                background=COLORS["tree_bg"],
                foreground=COLORS["tree_fg"],
                fieldbackground=COLORS["tree_bg"],
                rowheight=28,
                font=("Segoe UI", 9),
            )
            style.configure(
                "Dark.Treeview.Heading",
                background=COLORS["button_bg"],
                foreground=COLORS["accent"],
                font=("Segoe UI", 9, "bold"),
            )
            style.configure(
                "Dark.Horizontal.TProgressbar",
                troughcolor=COLORS["entry_bg"],
                background=COLORS["accent"],
            )
            style.configure(
                "Status.TLabel",
                background=COLORS["bg"],
                foreground=COLORS["weak"],
                font=("Segoe UI", 10),
            )
            style.configure(
                "Recommend.TLabel",
                background=COLORS["bg"],
                foreground=COLORS["medium"],
                font=("Segoe UI", 9),
            )
            style.configure(
                "StrengthWeak.TLabel",
                background=COLORS["bg"],
                foreground=COLORS["weak"],
                font=("Segoe UI", 10),
            )
            style.configure(
                "StrengthMedium.TLabel",
                background=COLORS["bg"],
                foreground=COLORS["medium"],
                font=("Segoe UI", 10),
            )
            style.configure(
                "StrengthStrong.TLabel",
                background=COLORS["bg"],
                foreground=COLORS["strong"],
                font=("Segoe UI", 10),
            )
        except Exception as error:
            app_logger.log_error(f"Ошибка настройки стилей: {error}")
            raise

    def _safe_destroy_root(self) -> None:
        """Безопасно закрывает главное окно, если оно ещё существует."""
        try:
            app_logger.log("ЗАКРЫТИЕ", "Попытка безопасного закрытия окна")
            if self.root.winfo_exists():
                app_logger.log("ЗАКРЫТИЕ", "Окно существует, вызов destroy()")
                self.root.destroy()
                app_logger.log("ЗАКРЫТИЕ", "✓ Окно закрыто успешно")
            else:
                app_logger.log("ЗАКРЫТИЕ", "Окно уже не существует")
        except tk.TclError as error:
            app_logger.log_error(f"Ошибка закрытия окна (TclError): {error}")
        except Exception as error:
            app_logger.log_error(f"Ошибка закрытия окна: {error}")

    def _setup_activity_tracking(self) -> None:
        """Включает отслеживание активности для автоблокировки после входа."""
        if self._activity_bound:
            return
        self.root.bind_all("<Key>", self._reset_activity, add="+")
        self.root.bind_all("<Button>", self._reset_activity, add="+")
        self._activity_bound = True
        app_logger.log("АКТИВНОСТЬ", "Отслеживание активности включено")

    def _run_startup_diagnostics(self) -> None:
        """Самодиагностика файлов при запуске."""
        try:
            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "=== НАЧАЛО ДИАГНОСТИКИ ===")
            
            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "Проверка ключа шифрования...")
            encryption_manager.ensure_key_file()
            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "✓ Ключ шифрования проверен")
            
            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "Проверка хеша мастер-пароля...")
            auth_manager.ensure_master_hash_file()
            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "✓ Хеш мастер-пароля проверен")
            
            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "Проверка файла паролей...")
            pwd_manager.ensure_passwords_file()
            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "✓ Файл паролей проверен")

            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "Запуск расширенной диагностики...")
            warnings = run_self_diagnostics(
                PASSWORDS_FILE,
                MASTER_HASH_FILE,
                KEY_FILE,
                LOG_FILE,
            )
            
            if warnings:
                app_logger.log("ДИАГНОСТИКА_ЗАПУСК", f"⚠ Найдено {len(warnings)} предупреждение(й)")
                for warning in warnings:
                    app_logger.log("ДИАГНОСТИКА_ПРЕДУПРЕЖДЕНИЕ", warning)
            else:
                app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "✓ Предупреждений не обнаружено")
            
            app_logger.log("ДИАГНОСТИКА_ЗАПУСК", "=== ДИАГНОСТИКА ЗАВЕРШЕНА ===")
            
            return warnings
        except Exception as error:
            app_logger.log_error(f"Ошибка диагностики: {error}")
            import traceback
            app_logger.log_error(f"Трассировка: {traceback.format_exc()}")
            return []

    def _reset_activity(self, _event: Any = None) -> None:
        """Сбрасывает таймер бездействия при активности пользователя."""
        if hasattr(self, "_schedule_auto_lock"):
            self._schedule_auto_lock()

    def run(self) -> None:
        """Запуск приложения: сначала авторизация, затем главное окно."""
        try:
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "=== ЗАПУСК ГЛАВНОГО ЦИКЛА ===")
            
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "Скрытие главного окна...")
            self.root.withdraw()
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "✓ Окно скрыто")
            
            first_run = auth_manager.is_first_run()
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", f"Первый запуск: {first_run}")
            
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "Показ диалога авторизации...")
            auth_success = self._show_auth_dialog(first_run=first_run)
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", f"Результат авторизации: {auth_success}")
            
            if not auth_success:
                app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "Авторизация отменена, закрытие приложения")
                self._safe_destroy_root()
                return
            
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "Построение главного окна...")
            self._build_main_window()
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "✓ Главное окно построено")
            
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "Отображение окна...")
            self.root.deiconify()
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "✓ Окно отображено")
            
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "Настройка отслеживания активности...")
            self._setup_activity_tracking()
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "✓ Отслеживание настроено")
            
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "Планирование автоблокировки...")
            self._schedule_auto_lock()
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "✓ Автоблокировка запланирована")
            
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "=== ЗАПУСК ОСНОВНОГО ЦИКЛА СОБЫТИЯ ===")
            self.root.mainloop()
            app_logger.log("ЗАПУСК_ПРИЛОЖЕНИЯ", "=== ОСНОВНОЙ ЦИКЛ ЗАВЕРШЕН ===")
            
        except Exception as error:
            app_logger.log_error(f"Критическая ошибка в run(): {error}")
            app_logger.log_error(f"Тип ошибки: {type(error).__name__}")
            import traceback
            app_logger.log_error(f"Трассировка: {traceback.format_exc()}")
            try:
                if self.root.winfo_exists():
                    messagebox.showerror("Ошибка", f"Произошла ошибка: {error}")
            except tk.TclError:
                pass
            self._safe_destroy_root()

    # ------------------------------------------------------------------ Auth
    def _show_auth_dialog(self, first_run: bool = False, auto_lock: bool = False) -> bool:
        """
        Окно авторизации / создания мастер-пароля.

        :return: True если пользователь успешно авторизован
        """
        try:
            app_logger.log("ДИАЛОГ_AUTH", f"Открытие диалога авторизации (first_run={first_run})")
            
            auth_window = tk.Toplevel(self.root)
            auth_window.title("Авторизация — Менеджер паролей")
            auth_window.geometry("440x360" if first_run else "440x280")
            auth_window.configure(bg=COLORS["bg"])
            auth_window.resizable(False, False)
            auth_window.transient(self.root)
            auth_window.grab_set()
            app_logger.log("ДИАЛОГ_AUTH", "✓ Окно авторизации создано")

            result = {"success": False, "cancelled": False}

            frame = ttk.Frame(auth_window, style="Dark.TFrame", padding=20)
            frame.pack(fill=tk.BOTH, expand=True)

            title = "Создание мастер-пароля" if first_run else "Вход в систему"
            ttk.Label(frame, text=title, style="Header.TLabel").pack(pady=(0, 15))

            if first_run:
                ttk.Label(
                    frame,
                    text="При первом запуске задайте мастер-пароль.\n"
                         "Он хранится только в виде SHA-256 хеша.\n"
                         "Нажмите Enter или кнопку «Создать».",
                    style="Dark.TLabel",
                    wraplength=380,
                ).pack(pady=(0, 10))

            ttk.Label(frame, text="Мастер-пароль:", style="Dark.TLabel").pack(anchor=tk.W)
            password_var = tk.StringVar()
            password_entry = ttk.Entry(frame, textvariable=password_var, show="•", width=40)
            password_entry.pack(pady=5, fill=tk.X)

            confirm_entry = None
            if first_run:
                ttk.Label(frame, text="Подтверждение:", style="Dark.TLabel").pack(anchor=tk.W, pady=(10, 0))
                confirm_var = tk.StringVar()
                confirm_entry = ttk.Entry(frame, textvariable=confirm_var, show="•", width=40)
                confirm_entry.pack(pady=5, fill=tk.X)
            else:
                confirm_var = None

            status_label = ttk.Label(frame, text="", style="Status.TLabel")
            status_label.pack(pady=5)

            def update_lockout_label() -> None:
                """Обновляет сообщение о блокировке каждую секунду."""
                if auth_manager.is_locked_out():
                    remaining = auth_manager.get_lockout_remaining()
                    status_label.config(text=f"Заблокировано. Осталось: {remaining} сек.")
                    auth_window.after(1000, update_lockout_label)
                else:
                    status_label.config(text="")

            if auth_manager.is_locked_out():
                update_lockout_label()

            def on_submit(_event: Any = None) -> None:
                try:
                    password = password_var.get()

                    if first_run:
                        confirm = confirm_var.get() if confirm_var else ""
                        if not password:
                            status_label.config(text="Введите мастер-пароль.")
                            return
                        if not confirm:
                            status_label.config(text="Подтвердите мастер-пароль.")
                            return
                        if password != confirm:
                            status_label.config(text="Пароли не совпадают.")
                            return
                        success, msg = auth_manager.create_master_password(password)
                    else:
                        if auth_manager.is_locked_out():
                            status_label.config(text=f"Подождите {auth_manager.get_lockout_remaining()} сек.")
                            return
                        if not password:
                            status_label.config(text="Введите мастер-пароль.")
                            return
                        success, msg = auth_manager.verify_password(password)

                    if success:
                        result["success"] = True
                        pwd_manager.set_authenticated(True)
                        load_ok, load_msg = pwd_manager.load_records()
                        if not load_ok:
                            status_label.config(text=load_msg)
                            pwd_manager.set_authenticated(False)
                            return
                        if first_run:
                            app_logger.log(
                                app_logger.EVENT_LOGIN_SUCCESS,
                                "Первичная настройка: мастер-пароль создан",
                            )
                        auth_window.grab_release()
                        auth_window.destroy()
                    else:
                        status_label.config(text=msg)
                        if auth_manager.is_locked_out():
                            update_lockout_label()
                except Exception as error:
                    app_logger.log_error(f"Ошибка авторизации: {error}")
                    status_label.config(text=f"Ошибка авторизации: {error}")

            def on_cancel() -> None:
                result["cancelled"] = True
                auth_window.grab_release()
                auth_window.destroy()

            btn_frame = ttk.Frame(frame, style="Dark.TFrame")
            btn_frame.pack(pady=15)
            submit_text = "Создать" if first_run else "Войти"
            submit_btn = ttk.Button(btn_frame, text=submit_text, style="Dark.TButton", command=on_submit)
            submit_btn.pack(side=tk.LEFT, padx=5)
            if not auto_lock:
                ttk.Button(btn_frame, text="Выход", style="Dark.TButton", command=on_cancel).pack(side=tk.LEFT, padx=5)

            password_entry.bind("<Return>", on_submit)
            if confirm_entry is not None:
                confirm_entry.bind("<Return>", on_submit)

            auth_window.protocol("WM_DELETE_WINDOW", on_cancel)
            password_entry.focus_set()
            auth_window.update_idletasks()
            app_logger.log("ДИАЛОГ_AUTH", "Ожидание действия пользователя...")
            self.root.wait_window(auth_window)
            app_logger.log("ДИАЛОГ_AUTH", f"Результат: success={result['success']}, cancelled={result['cancelled']}")
            return result["success"]
        except Exception as error:
            app_logger.log_error(f"Ошибка в _show_auth_dialog: {error}")
            import traceback
            app_logger.log_error(f"Трассировка: {traceback.format_exc()}")
            return False

    def _lock_application(self) -> None:
        """Автоблокировка после 5 минут бездействия."""
        app_logger.log(app_logger.EVENT_AUTO_LOCK, "Автоблокировка: требуется повторный ввод пароля")
        pwd_manager.set_authenticated(False)
        self._clear_form()

        if hasattr(self, "tree"):
            try:
                self._refresh_table([])
            except Exception:
                pass

        for widget in self.root.winfo_children():
            widget.destroy()

        if self._show_auth_dialog(auto_lock=True):
            self._build_main_window()
            self._schedule_auto_lock()
        else:
            self._safe_destroy_root()

    def _schedule_auto_lock(self) -> None:
        """Планирует проверку бездействия."""
        if self._auto_lock_job:
            self.root.after_cancel(self._auto_lock_job)
        self._auto_lock_job = self.root.after(AUTO_LOCK_MS, self._lock_application)

    # ---------------------------------------------------------- Main window
    def _build_main_window(self) -> None:
        """Построение главного окна приложения."""
        try:
            app_logger.log("UI_MAIN", "=== ПОСТРОЕНИЕ ГЛАВНОГО ОКНА ===")
            
            for widget in self.root.winfo_children():
                widget.destroy()

            main = ttk.Frame(self.root, style="Dark.TFrame", padding=10)
            main.pack(fill=tk.BOTH, expand=True)
            app_logger.log("UI_MAIN", "✓ Основной фрейм создан")

            ttk.Label(main, text="Менеджер паролей", style="Header.TLabel").pack(anchor=tk.W)

            # --- Поиск ---
            search_frame = ttk.Frame(main, style="Dark.TFrame")
            search_frame.pack(fill=tk.X, pady=(10, 5))
            ttk.Label(search_frame, text="Поиск по сайту:", style="Dark.TLabel").pack(side=tk.LEFT)
            self.search_var = tk.StringVar()
            self.search_var.trace_add("write", lambda *_: self._on_search())
            ttk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=8)
            app_logger.log("UI_MAIN", "✓ Поиск добавлен")

            # --- Форма ввода ---
            form = ttk.LabelFrame(main, text="  Новая / редактируемая запись  ", padding=10)
            form.pack(fill=tk.X, pady=5)

            fields = ttk.Frame(form, style="Dark.TFrame")
            fields.pack(fill=tk.X)

            self.site_var = tk.StringVar()
            self.login_var = tk.StringVar()
            self.password_var = tk.StringVar()
            self.password_var.trace_add("write", lambda *_: self._update_strength_indicator())

            for col, (label, var) in enumerate(
                [("Сайт", self.site_var), ("Логин", self.login_var), ("Пароль", self.password_var)]
            ):
                ttk.Label(fields, text=f"{label}:", style="Dark.TLabel").grid(row=0, column=col * 2, sticky=tk.W, padx=4)
                show = "•" if label == "Пароль" else ""
                entry = ttk.Entry(fields, textvariable=var, width=22, show=show)
                entry.grid(row=1, column=col * 2, padx=4, pady=2)

            app_logger.log("UI_MAIN", "✓ Форма ввода добавлена")

            # --- Индикатор надёжности пароля ---
            strength_frame = ttk.Frame(form, style="Dark.TFrame")
            strength_frame.pack(fill=tk.X, pady=(8, 0))
            ttk.Label(strength_frame, text="Надёжность:", style="Dark.TLabel").pack(side=tk.LEFT)
            self.strength_bar = ttk.Progressbar(strength_frame, length=200, mode="determinate", style="Dark.Horizontal.TProgressbar")
            self.strength_bar.pack(side=tk.LEFT, padx=8)
            self.strength_label = ttk.Label(strength_frame, text="—", style="Dark.TLabel")
            self.strength_label.pack(side=tk.LEFT)
            self._strength_style = "Dark.TLabel"
            self.recommend_label = ttk.Label(form, text="", style="Recommend.TLabel", wraplength=700)
            self.recommend_label.pack(anchor=tk.W, pady=(4, 0))
            app_logger.log("UI_MAIN", "✓ Индикатор надёжности добавлен")

            # --- Кнопки управления ---
            btn_frame1 = ttk.Frame(main, style="Dark.TFrame")
            btn_frame1.pack(fill=tk.X, pady=8)

            buttons_row1 = [
                ("Сохранить запись", self._save_record),
                ("Редактировать запись", self._edit_record),
                ("Удалить запись", self._delete_record),
                ("Показать записи", self._show_records),
                ("Скопировать пароль", self._copy_password),
                ("Сгенерировать пароль", self._generate_password_dialog),
            ]
            for text, command in buttons_row1:
                ttk.Button(btn_frame1, text=text, style="Dark.TButton", command=command).pack(side=tk.LEFT, padx=3, pady=2)

            btn_frame2 = ttk.Frame(main, style="Dark.TFrame")
            btn_frame2.pack(fill=tk.X, pady=2)

            buttons_row2 = [
                ("Создать резервную копию", self._create_backup),
                ("Восстановить резервную копию", self._restore_backup),
                ("Экспорт в PDF", self._export_pdf),
                ("QR-код записи", self._show_qr_code),
                ("История действий", self._show_history),
                ("Информация о защите данных", self._show_protection_info),
            ]
            for text, command in buttons_row2:
                ttk.Button(btn_frame2, text=text, style="Dark.TButton", command=command).pack(side=tk.LEFT, padx=3, pady=2)
            
            app_logger.log("UI_MAIN", "✓ Кнопки добавлены (12 шт)")

            # --- Таблица записей ---
            table_frame = ttk.Frame(main, style="Dark.TFrame")
            table_frame.pack(fill=tk.BOTH, expand=True, pady=5)

            columns = ("site", "login", "password", "created_at")
            self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="Dark.Treeview")
            self.tree.heading("site", text="Сайт")
            self.tree.heading("login", text="Логин")
            self.tree.heading("password", text="Пароль")
            self.tree.heading("created_at", text="Дата создания")
            self.tree.column("site", width=160)
            self.tree.column("login", width=160)
            self.tree.column("password", width=160)
            self.tree.column("created_at", width=140)

            scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
            self.tree.configure(yscrollcommand=scrollbar.set)
            self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
            app_logger.log("UI_MAIN", "✓ Таблица добавлена")

            # --- Статистика ---
            stats_frame = ttk.LabelFrame(main, text="  Статистика безопасности  ", padding=8)
            stats_frame.pack(fill=tk.X, pady=5)
            self.stats_label = ttk.Label(stats_frame, text="", style="Dark.TLabel")
            self.stats_label.pack(anchor=tk.W)
            app_logger.log("UI_MAIN", "✓ Статистика добавлена")

            self._show_records()
            app_logger.log("UI_MAIN", "=== ГЛАВНОЕ ОКНО ПОСТРОЕНО ===")
            
        except Exception as error:
            app_logger.log_error(f"Ошибка построения главного окна: {error}")
            import traceback
            app_logger.log_error(f"Трассировка: {traceback.format_exc()}")
            raise

    def _set_strength_label(self, text: str, level: str = "default") -> None:
        """Обновляет текст и цвет индикатора надёжности через ttk-стили."""
        style_map = {
            "default": "Dark.TLabel",
            "слабый": "StrengthWeak.TLabel",
            "средний": "StrengthMedium.TLabel",
            "сильный": "StrengthStrong.TLabel",
        }
        new_style = style_map.get(level, "Dark.TLabel")
        if new_style != self._strength_style:
            self.strength_label.configure(style=new_style)
            self._strength_style = new_style
        self.strength_label.config(text=text)

    def _update_strength_indicator(self) -> None:
        """Обновляет индикатор надёжности пароля в форме."""
        try:
            if not hasattr(self, "strength_bar"):
                return

            password = self.password_var.get()
            if not password:
                self.strength_bar["value"] = 0
                self._set_strength_label("—")
                self.recommend_label.config(text="")
                return

            score, level, recommendations = analyze_password_strength(password)
            self.strength_bar["value"] = score
            self._set_strength_label(f"{score}/100 — {level}", level)

            if recommendations:
                self.recommend_label.config(text="Рекомендации: " + "; ".join(recommendations))
            else:
                self.recommend_label.config(text="")
        except Exception as error:
            app_logger.log_error(f"Ошибка индикатора надёжности: {error}")

    def _refresh_table(self, indexed_records: list[tuple[int, dict[str, Any]]]) -> None:
        """Обновляет содержимое таблицы."""
        try:
            for item in self.tree.get_children():
                self.tree.delete(item)
            for storage_index, record in indexed_records:
                self.tree.insert(
                    "",
                    tk.END,
                    iid=str(storage_index),
                    values=(
                        record["site"],
                        record["login"],
                        record["password"],
                        record["created_at"],
                    ),
                )
            records = [record for _, record in indexed_records]
            self._update_statistics(records)
        except Exception as error:
            app_logger.log_error(f"Ошибка обновления таблицы: {error}")

    def _update_statistics(self, records: list[dict[str, Any]]) -> None:
        """Обновляет блок статистики."""
        stats = compute_statistics(records)
        text = (
            f"Всего записей: {stats['total']}  |  "
            f"Средняя длина паролей: {stats['avg_length']}  |  "
            f"Сильных паролей: {stats['strong_count']}  |  "
            f"Процент сильных: {stats['strong_percent']}%"
        )
        self.stats_label.config(text=text)

    def _on_search(self) -> None:
        """Фильтрация таблицы по поисковому запросу."""
        try:
            query = self.search_var.get()
            indexed_records = pwd_manager.search_by_site(query)
            self._refresh_table(indexed_records)
        except Exception as error:
            app_logger.log_error(f"Ошибка поиска: {error}")

    def _on_tree_select(self, _event: Any = None) -> None:
        """Заполнение формы при выборе строки таблицы."""
        try:
            selection = self.tree.selection()
            if not selection:
                self._selected_index = None
                return
            storage_index = int(selection[0])
            self._selected_index = storage_index
            records = pwd_manager.get_records()
            if 0 <= storage_index < len(records):
                record = records[storage_index]
                self.site_var.set(record["site"])
                self.login_var.set(record["login"])
                self.password_var.set(record["password"])
        except Exception as error:
            app_logger.log_error(f"Ошибка выбора записи: {error}")

    def _clear_form(self) -> None:
        """Очищает поля формы."""
        self.site_var.set("")
        self.login_var.set("")
        self.password_var.set("")
        self._selected_index = None

    def _save_record(self) -> None:
        """Сохранение новой записи."""
        try:
            success, message = pwd_manager.add_record(
                self.site_var.get(),
                self.login_var.get(),
                self.password_var.get(),
            )
            if success:
                messagebox.showinfo("Успех", "Запись сохранена.")
                self._clear_form()
                self._on_search()
            else:
                messagebox.showwarning("Внимание", message)
        except Exception as error:
            app_logger.log_error(f"Ошибка сохранения: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _edit_record(self) -> None:
        """Редактирование выбранной записи."""
        try:
            if self._selected_index is None:
                messagebox.showwarning("Внимание", "Выберите запись в таблице.")
                return
            success, message = pwd_manager.update_record(
                self._selected_index,
                self.site_var.get(),
                self.login_var.get(),
                self.password_var.get(),
            )
            if success:
                messagebox.showinfo("Успех", "Запись обновлена.")
                self._on_search()
            else:
                messagebox.showwarning("Внимание", message)
        except Exception as error:
            app_logger.log_error(f"Ошибка редактирования: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _delete_record(self) -> None:
        """Удаление выбранной записи."""
        try:
            if self._selected_index is None:
                messagebox.showwarning("Внимание", "Выберите запись в таблице.")
                return
            if not messagebox.askyesno("Подтверждение", "Удалить выбранную запись?"):
                return
            success, message = pwd_manager.delete_record(self._selected_index)
            if success:
                messagebox.showinfo("Успех", "Запись удалена.")
                self._clear_form()
                self._on_search()
            else:
                messagebox.showwarning("Внимание", message)
        except Exception as error:
            app_logger.log_error(f"Ошибка удаления: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _show_records(self) -> None:
        """Загрузка и отображение всех записей."""
        try:
            success, message = pwd_manager.load_records()
            if not success:
                messagebox.showerror("Ошибка", message)
                return
            self.search_var.set("")
            indexed = list(enumerate(pwd_manager.get_records()))
            self._refresh_table(indexed)
        except Exception as error:
            app_logger.log_error(f"Ошибка загрузки записей: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _copy_password(self) -> None:
        """Копирование пароля выбранной записи в буфер обмена."""
        try:
            password = self.password_var.get()
            if not password:
                messagebox.showwarning("Внимание", "Нет пароля для копирования.")
                return
            pyperclip.copy(password)
            messagebox.showinfo("Успех", "Пароль скопирован в буфер обмена.")
        except Exception as error:
            app_logger.log_error(f"Ошибка копирования: {error}")
            messagebox.showerror("Ошибка", f"Не удалось скопировать: {error}")

    def _generate_password_dialog(self) -> None:
        """Диалог генератора надёжных паролей."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Генератор паролей")
        dialog.geometry("380x320")
        dialog.configure(bg=COLORS["bg"])
        dialog.grab_set()

        frame = ttk.Frame(dialog, style="Dark.TFrame", padding=15)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Генератор надёжных паролей", style="Header.TLabel").pack(pady=(0, 10))

        length_var = tk.IntVar(value=16)
        ttk.Label(frame, text="Длина (12–20):", style="Dark.TLabel").pack(anchor=tk.W)
        length_scale = ttk.Scale(frame, from_=12, to=20, orient=tk.HORIZONTAL, variable=length_var)
        length_scale.pack(fill=tk.X, pady=4)
        length_display = ttk.Label(frame, text="16", style="Dark.TLabel")
        length_display.pack(anchor=tk.W)

        def update_length_label(_val: Any = None) -> None:
            length_display.config(text=str(int(length_var.get())))

        length_scale.configure(command=update_length_label)

        lower_var = tk.BooleanVar(value=True)
        upper_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        special_var = tk.BooleanVar(value=True)

        for text, var in [
            ("Строчные буквы (a-z)", lower_var),
            ("Заглавные буквы (A-Z)", upper_var),
            ("Цифры (0-9)", digits_var),
            ("Специальные символы", special_var),
        ]:
            ttk.Checkbutton(frame, text=text, variable=var).pack(anchor=tk.W)

        result_var = tk.StringVar()

        def do_generate() -> None:
            try:
                pwd = generate_password(
                    length=int(length_var.get()),
                    use_lower=lower_var.get(),
                    use_upper=upper_var.get(),
                    use_digits=digits_var.get(),
                    use_special=special_var.get(),
                )
                result_var.set(pwd)
                app_logger.log(app_logger.EVENT_GENERATE, "Сгенерирован новый пароль")
            except Exception as error:
                app_logger.log_error(f"Ошибка генерации пароля: {error}")

        ttk.Button(frame, text="Сгенерировать", style="Dark.TButton", command=do_generate).pack(pady=8)
        ttk.Entry(frame, textvariable=result_var, width=40).pack(pady=4)

        def insert_password() -> None:
            pwd = result_var.get()
            if pwd:
                self.password_var.set(pwd)
                dialog.destroy()

        ttk.Button(frame, text="Вставить в поле пароля", style="Dark.TButton", command=insert_password).pack(pady=5)
        do_generate()

    def _create_backup(self) -> None:
        """Создание резервной копии."""
        try:
            success, message = backup_manager.create_backup()
            if success:
                messagebox.showinfo("Успех", f"Резервная копия создана:\n{message}")
            else:
                messagebox.showwarning("Внимание", message)
        except Exception as error:
            app_logger.log_error(f"Ошибка резервного копирования: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _restore_backup(self) -> None:
        """Восстановление из резервной копии."""
        try:
            filepath = filedialog.askopenfilename(
                title="Выберите файл резервной копии",
                initialdir=os.path.join(PROJECT_DIR, "backups"),
                filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")],
            )
            if not filepath:
                return
            if not messagebox.askyesno("Подтверждение", "Восстановить данные из выбранной копии?"):
                return
            success, message = backup_manager.restore_backup(filepath)
            if success:
                pwd_manager.load_records()
                self._on_search()
                messagebox.showinfo("Успех", message)
            else:
                messagebox.showwarning("Внимание", message)
        except Exception as error:
            app_logger.log_error(f"Ошибка восстановления: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _export_pdf(self) -> None:
        """Экспорт отчёта в PDF."""
        try:
            from datetime import datetime

            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas

            os.makedirs(EXPORTS_DIR, exist_ok=True)
            records = pwd_manager.get_records()
            stats = compute_statistics(records)
            timestamp = datetime.now().strftime("%Y_%m_%d_%H_%M")
            filepath = os.path.join(EXPORTS_DIR, f"report_{timestamp}.pdf")

            pdf = canvas.Canvas(filepath, pagesize=A4)
            width, height = A4
            y = height - 50

            pdf.setFont("Helvetica-Bold", 16)
            pdf.drawString(50, y, "Отчёт — Менеджер паролей")
            y -= 30

            pdf.setFont("Helvetica", 11)
            pdf.drawString(50, y, f"Дата создания отчёта: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
            y -= 25
            pdf.drawString(50, y, f"Количество записей: {stats['total']}")
            y -= 20
            pdf.drawString(50, y, f"Средняя длина паролей: {stats['avg_length']}")
            y -= 20
            pdf.drawString(50, y, f"Сильных паролей: {stats['strong_count']} ({stats['strong_percent']}%)")
            y -= 30

            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawString(50, y, "Список сайтов:")
            y -= 20
            pdf.setFont("Helvetica", 10)

            for record in records:
                if y < 60:
                    pdf.showPage()
                    y = height - 50
                    pdf.setFont("Helvetica", 10)
                pdf.drawString(60, y, f"• {record['site']} — {record['created_at']}")
                y -= 16

            pdf.save()
            app_logger.log(app_logger.EVENT_EXPORT, f"Экспорт PDF: {os.path.basename(filepath)}")
            messagebox.showinfo("Успех", f"Отчёт сохранён:\n{filepath}")
        except Exception as error:
            app_logger.log_error(f"Ошибка экспорта PDF: {error}")
            messagebox.showerror("Ошибка", f"Не удалось создать PDF: {error}")

    def _show_qr_code(self) -> None:
        """Генерация и отображение QR-кода для выбранной записи."""
        try:
            if self._selected_index is None:
                messagebox.showwarning("Внимание", "Выберите запись в таблице.")
                return

            site = self.site_var.get()
            login = self.login_var.get()
            password = self.password_var.get()
            qr_data = f"SITE:{site}\nLOGIN:{login}\nPASS:{password}"

            os.makedirs(EXPORTS_DIR, exist_ok=True)
            from datetime import datetime

            filename = f"qr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            filepath = os.path.join(EXPORTS_DIR, filename)

            if not save_qr_code(qr_data, filepath):
                messagebox.showerror("Ошибка", "Не удалось создать QR-код.")
                return

            qr_window = tk.Toplevel(self.root)
            qr_window.title(f"QR-код — {site}")
            qr_window.configure(bg=COLORS["bg"])
            qr_window.geometry("320x380")

            from PIL import Image, ImageTk

            img = Image.open(filepath)
            img = img.resize((250, 250), Image.Resampling.LANCZOS)
            photo = ImageTk.PhotoImage(img)

            label = ttk.Label(qr_window, image=photo, background=COLORS["bg"])
            label.image = photo  # type: ignore[attr-defined]
            label.pack(pady=15)

            ttk.Label(
                qr_window,
                text=f"Сохранено: {filename}",
                style="Dark.TLabel",
            ).pack()
        except Exception as error:
            app_logger.log_error(f"Ошибка QR-кода: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _show_history(self) -> None:
        """Окно истории действий на основе журнала."""
        try:
            history_window = tk.Toplevel(self.root)
            history_window.title("История действий")
            history_window.geometry("700x450")
            history_window.configure(bg=COLORS["bg"])

            frame = ttk.Frame(history_window, style="Dark.TFrame", padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(frame, text="Последние действия", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 8))

            text_widget = tk.Text(
                frame,
                bg=COLORS["entry_bg"],
                fg=COLORS["fg"],
                font=("Consolas", 9),
                wrap=tk.WORD,
            )
            text_widget.pack(fill=tk.BOTH, expand=True)

            scrollbar = ttk.Scrollbar(frame, command=text_widget.yview)
            text_widget.configure(yscrollcommand=scrollbar.set)

            entries = app_logger.get_recent_entries(100)
            if entries:
                text_widget.insert(tk.END, "\n".join(entries))
            else:
                text_widget.insert(tk.END, "Журнал пуст.")
            text_widget.config(state=tk.DISABLED)
        except Exception as error:
            app_logger.log_error(f"Ошибка окна истории: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _show_protection_info(self) -> None:
        """Информационное окно «Виды защиты информации»."""
        info_text = """
ВИДЫ ЗАЩИТЫ ИНФОРМАЦИИ

1. Физическая защита
   Охрана помещений, сейфы, контроль доступа, видеонаблюдение.
   Препятствует несанкционированному физическому доступу к носителям данных.

2. Программная защита
   Шифрование, аутентификация, антивирусы, контроль целостности.
   Данное приложение использует SHA-256, Fernet и безопасное хранение.

3. Аппаратная защита
   TPM-модули, аппаратные ключи (HSM), смарт-карты, биометрические сканеры.
   Обеспечивают защиту на уровне оборудования.

4. Организационная защита
   Политики безопасности, инструкции, разграничение прав, обучение персонала.
   Регламентирует работу с конфиденциальной информацией.

5. Законодательная защита
   ФЗ «О персональных данных», GDPR, уголовная ответственность за утечки.
   Правовые механизмы защиты информации.

6. Психологическая защита
   Повышение осведомлённости, противодействие социальной инженерии,
   формирование культуры информационной безопасности.

Реализованные меры в «Менеджере паролей»:
• Хеширование мастер-пароля (SHA-256)
• Шифрование данных (Fernet / AES)
• Защита от перебора пароля
• Автоблокировка при бездействии
• Журналирование всех действий
• Резервное копирование
"""
        try:
            info_window = tk.Toplevel(self.root)
            info_window.title("Виды защиты информации")
            info_window.geometry("620x520")
            info_window.configure(bg=COLORS["bg"])

            frame = ttk.Frame(info_window, style="Dark.TFrame", padding=10)
            frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(frame, text="Информация о защите данных", style="Header.TLabel").pack(anchor=tk.W)

            text_widget = tk.Text(
                frame,
                bg=COLORS["entry_bg"],
                fg=COLORS["fg"],
                font=("Segoe UI", 10),
                wrap=tk.WORD,
                padx=10,
                pady=10,
            )
            text_widget.pack(fill=tk.BOTH, expand=True, pady=8)
            text_widget.insert(tk.END, info_text.strip())
            text_widget.config(state=tk.DISABLED)
        except Exception as error:
            app_logger.log_error(f"Ошибка информационного окна: {error}")
            messagebox.showerror("Ошибка", str(error))


def main() -> None:
    """Точка входа приложения."""
    try:
        print("=" * 80)
        print("НАЧАЛО ЗАПУСКА ПРИЛОЖЕНИЯ МЕНЕДЖЕР ПАРОЛЕЙ")
        print("=" * 80)
        app_logger.log("MAIN", "=== НАЧАЛО ВЫПОЛНЕНИЯ main() ===")
        
        app = PasswordManagerApp()
        app_logger.log("MAIN", "✓ Объект приложения создан")
        
        app_logger.log("MAIN", "Вызов app.run()...")
        app.run()
        app_logger.log("MAIN", "✓ app.run() завершился")
        
        print("=" * 80)
        print("ПРИЛОЖЕНИЕ ЗАВЕРШИЛО РАБОТУ УСПЕШНО")
        print("=" * 80)
        app_logger.log("MAIN", "=== main() ЗАВЕРШЕНА УСПЕШНО ===")
        
    except Exception as error:
        print("=" * 80)
        print(f"КРИТИЧЕСКАЯ ОШИБКА: {error}")
        print(f"Тип: {type(error).__name__}")
        print("=" * 80)
        app_logger.log_error(f"Необработанная ошибка запуска: {error}")
        app_logger.log_error(f"Тип ошибки: {type(error).__name__}")
        import traceback
        app_logger.log_error(f"Трассировка: {traceback.format_exc()}")
        messagebox.showerror("Критическая ошибка", str(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
