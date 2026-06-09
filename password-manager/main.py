"""
Главный модуль приложения «Менеджер паролей» — УПРОЩЁННАЯ ВЕРСИЯ.

Упрощённый подход к отрисовке без сложной архитектуры.
Точка входа: авторизация, главное окно, все функции GUI.
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
            print("DEBUG: Инициализация PasswordManagerApp")
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "=== НАЧАЛО ИНИЦИАЛИЗАЦИИ ПРИЛОЖЕНИЯ ===")
            
            # Создаём корневое окно СРАЗУ
            self.root = tk.Tk()
            print("DEBUG: Tkinter Tk() создан успешно")
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Tkinter корень создан")
            
            # Минимальная настройка окна
            self.root.title("Менеджер паролей — Защита информации")
            self.root.geometry("1000x650")
            self.root.minsize(800, 500)
            
            print("DEBUG: Базовые свойства окна установлены")
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Окно настроено (1000x650)")

            # Инициализируем переменные
            self._selected_index: Optional[int] = None
            self._auto_lock_job: Optional[str] = None
            self._activity_bound = False
            
            # Флаг для безопасности
            self._is_closing = False

            # Диагностика - БЕЗ UI
            print("DEBUG: Запуск диагностики...")
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "=== НАЧАЛО ДИАГНОСТИКИ ===")
            
            encryption_manager.ensure_key_file()
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Ключ шифрования проверен")
            
            auth_manager.ensure_master_hash_file()
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Хеш мастер-пароля проверен")
            
            pwd_manager.ensure_passwords_file()
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Файл паролей проверен")

            warnings = run_self_diagnostics(
                PASSWORDS_FILE,
                MASTER_HASH_FILE,
                KEY_FILE,
                LOG_FILE,
            )
            
            if warnings:
                app_logger.log("ИНИЦИАЛИЗАЦИЯ", f"⚠ Найдено {len(warnings)} предупреждение(й)")
            else:
                app_logger.log("ИНИЦИАЛИЗАЦИЯ", "✓ Предупреждений не обнаружено")

            print("DEBUG: Диагностика завершена")
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "=== ДИАГНОСТИКА ЗАВЕРШЕНА ===")
            app_logger.log(app_logger.EVENT_START, "Запуск приложения «Менеджер паролей»")
            app_logger.log("ИНИЦИАЛИЗАЦИЯ", "=== ИНИЦИАЛИЗАЦИЯ ЗАВЕРШЕНА ===")
            print("DEBUG: PasswordManagerApp инициализирована успешно")
            
        except Exception as error:
            print(f"DEBUG: КРИТИЧЕСКАЯ ОШИБКА в __init__: {error}")
            app_logger.log_error(f"КРИТИЧЕСКАЯ ОШИБКА ИНИЦИАЛИЗАЦИИ: {error}")
            app_logger.log_error(f"Тип ошибки: {type(error).__name__}")
            import traceback
            app_logger.log_error(f"Трассировка: {traceback.format_exc()}")
            raise

    def run(self) -> None:
        """Главный цикл приложения."""
        try:
            print("DEBUG: Начало run()")
            app_logger.log("ЗАПУСК", "=== НАЧАЛО run() ===")
            
            # Проверяем первый запуск
            first_run = auth_manager.is_first_run()
            print(f"DEBUG: first_run = {first_run}")
            app_logger.log("ЗАПУСК", f"Первый запуск: {first_run}")
            
            # АВТОРИЗАЦИЯ
            print("DEBUG: Показываем диалог авторизации")
            app_logger.log("ЗАПУСК", "Показ диалога авторизации...")
            
            if not self._show_auth_dialog(first_run=first_run):
                print("DEBUG: Авторизация отменена")
                app_logger.log("ЗАПУСК", "Авторизация отменена пользователем")
                self._safe_close()
                return
            
            print("DEBUG: Авторизация успешна")
            app_logger.log("ЗАПУСК", "✓ Авторизация успешна")
            
            # ПОСТРОЕНИЕ UI
            print("DEBUG: Построение главного окна")
            app_logger.log("ЗАПУСК", "Построение главного окна...")
            self._build_main_window()
            print("DEBUG: Главное окно построено")
            app_logger.log("ЗАПУСК", "✓ Главное окно построено")
            
            # ПОКАЗЫВАЕМ ОКНО
            print("DEBUG: Показываем окно (update + deiconify)")
            self.root.update_idletasks()
            self.root.deiconify()
            print("DEBUG: Окно видимо")
            app_logger.log("ЗАПУСК", "✓ Окно отображено")
            
            # Отслеживание активности
            self._setup_activity_tracking()
            self._schedule_auto_lock()
            
            print("DEBUG: Начало mainloop()")
            app_logger.log("ЗАПУСК", "=== НАЧАЛО ОСНОВНОГО ЦИКЛА СОБЫТИЯ ===")
            
            # ГЛАВНЫЙ ЦИКЛ
            self.root.mainloop()
            
            print("DEBUG: mainloop() завершён")
            app_logger.log("ЗАПУСК", "=== ОСНОВНОЙ ЦИКЛ ЗАВЕРШЕН ===")
            
        except Exception as error:
            print(f"DEBUG: ОШИБКА в run(): {error}")
            app_logger.log_error(f"Критическая ошибка в run(): {error}")
            import traceback
            app_logger.log_error(f"Трассировка: {traceback.format_exc()}")
            self._safe_close()

    def _safe_close(self) -> None:
        """Безопасное закрытие приложения."""
        if self._is_closing:
            return
        self._is_closing = True
        try:
            if self.root.winfo_exists():
                self.root.destroy()
        except Exception:
            pass

    def _setup_activity_tracking(self) -> None:
        """Отслеживание активности."""
        if self._activity_bound:
            return
        self.root.bind_all("<Key>", lambda e: self._schedule_auto_lock(), add="+")
        self.root.bind_all("<Button>", lambda e: self._schedule_auto_lock(), add="+")
        self._activity_bound = True

    def _schedule_auto_lock(self) -> None:
        """Перепланирование автоблокировки."""
        if self._auto_lock_job:
            self.root.after_cancel(self._auto_lock_job)
        self._auto_lock_job = self.root.after(AUTO_LOCK_MS, self._lock_application)

    def _lock_application(self) -> None:
        """Автоблокировка."""
        app_logger.log(app_logger.EVENT_AUTO_LOCK, "Автоблокировка")
        pwd_manager.set_authenticated(False)
        
        for widget in self.root.winfo_children():
            widget.destroy()
        
        if self._show_auth_dialog(auto_lock=True):
            self._build_main_window()
            self._schedule_auto_lock()
        else:
            self._safe_close()

    # ================================================================ AUTH
    def _show_auth_dialog(self, first_run: bool = False, auto_lock: bool = False) -> bool:
        """Диалог авторизации."""
        try:
            print(f"DEBUG: Открытие диалога авторизации (first_run={first_run})")
            
            auth_window = tk.Toplevel(self.root)
            auth_window.title("Авторизация — Менеджер паролей")
            auth_window.geometry("440x360" if first_run else "440x280")
            auth_window.resizable(False, False)
            auth_window.transient(self.root)
            auth_window.grab_set()

            result = {"success": False}

            # Простой фрейм без стилей
            frame = tk.Frame(auth_window, bg=COLORS["bg"])
            frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

            # Заголовок
            title = tk.Label(
                frame,
                text="Создание мастер-пароля" if first_run else "Вход в систему",
                font=("Arial", 14, "bold"),
                bg=COLORS["bg"],
                fg=COLORS["header"],
            )
            title.pack(pady=(0, 15))

            if first_run:
                tk.Label(
                    frame,
                    text="При первом запуске задайте мастер-пароль.\n"
                         "Он хранится только в виде SHA-256 хеша.",
                    font=("Arial", 10),
                    bg=COLORS["bg"],
                    fg=COLORS["fg"],
                    wraplength=350,
                ).pack(pady=(0, 15))

            # Пароль
            tk.Label(frame, text="Мастер-пароль:", bg=COLORS["bg"], fg=COLORS["fg"]).pack(anchor=tk.W)
            password_var = tk.StringVar()
            password_entry = tk.Entry(frame, textvariable=password_var, show="•", width=40, bg=COLORS["entry_bg"], fg=COLORS["fg"], insertbackground=COLORS["fg"])
            password_entry.pack(pady=5, fill=tk.X)

            # Подтверждение
            confirm_var = None
            confirm_entry = None
            if first_run:
                tk.Label(frame, text="Подтверждение:", bg=COLORS["bg"], fg=COLORS["fg"]).pack(anchor=tk.W, pady=(10, 0))
                confirm_var = tk.StringVar()
                confirm_entry = tk.Entry(frame, textvariable=confirm_var, show="•", width=40, bg=COLORS["entry_bg"], fg=COLORS["fg"], insertbackground=COLORS["fg"])
                confirm_entry.pack(pady=5, fill=tk.X)

            # Статус
            status_label = tk.Label(frame, text="", bg=COLORS["bg"], fg=COLORS["weak"], font=("Arial", 9))
            status_label.pack(pady=5)

            def update_lockout() -> None:
                if auth_manager.is_locked_out():
                    remaining = auth_manager.get_lockout_remaining()
                    status_label.config(text=f"Заблокировано. Осталось: {remaining} сек.")
                    auth_window.after(1000, update_lockout)

            if auth_manager.is_locked_out():
                update_lockout()

            def on_submit() -> None:
                password = password_var.get()

                if first_run:
                    confirm = confirm_var.get() if confirm_var else ""
                    if password != confirm:
                        status_label.config(text="Пароли не совпадают")
                        return
                    success, msg = auth_manager.create_master_password(password)
                else:
                    if auth_manager.is_locked_out():
                        status_label.config(text=f"Подождите {auth_manager.get_lockout_remaining()} сек")
                        return
                    success, msg = auth_manager.verify_password(password)

                if success:
                    result["success"] = True
                    pwd_manager.set_authenticated(True)
                    pwd_manager.load_records()
                    auth_window.destroy()
                else:
                    status_label.config(text=msg)

            # Кнопки
            btn_frame = tk.Frame(frame, bg=COLORS["bg"])
            btn_frame.pack(pady=15)
            
            submit_btn = tk.Button(
                btn_frame,
                text="Создать" if first_run else "Войти",
                command=on_submit,
                bg=COLORS["button_bg"],
                fg=COLORS["button_fg"],
                padx=15,
                pady=5,
            )
            submit_btn.pack(side=tk.LEFT, padx=5)
            
            if not auto_lock:
                tk.Button(
                    btn_frame,
                    text="Выход",
                    command=auth_window.destroy,
                    bg=COLORS["button_bg"],
                    fg=COLORS["button_fg"],
                    padx=15,
                    pady=5,
                ).pack(side=tk.LEFT, padx=5)

            password_entry.bind("<Return>", lambda e: on_submit())
            if confirm_entry:
                confirm_entry.bind("<Return>", lambda e: on_submit())

            password_entry.focus()
            
            print("DEBUG: Диалог авторизации ожидает действия")
            self.root.wait_window(auth_window)
            
            print(f"DEBUG: Результат авторизации: {result['success']}")
            return result["success"]
            
        except Exception as error:
            print(f"DEBUG: Ошибка в диалоге авторизации: {error}")
            app_logger.log_error(f"Ошибка в диалоге авторизации: {error}")
            return False

    # ================================================================ UI
    def _build_main_window(self) -> None:
        """Построение главного окна - МАКСИМАЛЬНО ПРОСТО."""
        try:
            print("DEBUG: _build_main_window() начало")
            
            # Очищаем окно
            for widget in self.root.winfo_children():
                widget.destroy()
            
            # Главный контейнер
            main = tk.Frame(self.root, bg=COLORS["bg"])
            main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Заголовок
            title = tk.Label(main, text="Менеджер паролей", font=("Arial", 16, "bold"), bg=COLORS["bg"], fg=COLORS["header"])
            title.pack(anchor=tk.W, pady=(0, 10))
            
            # ========== ПОИСК ==========
            search_frame = tk.Frame(main, bg=COLORS["bg"])
            search_frame.pack(fill=tk.X, pady=(0, 10))
            tk.Label(search_frame, text="Поиск:", bg=COLORS["bg"], fg=COLORS["fg"]).pack(side=tk.LEFT)
            self.search_var = tk.StringVar()
            self.search_var.trace_add("write", lambda *_: self._on_search())
            search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=30, bg=COLORS["entry_bg"], fg=COLORS["fg"])
            search_entry.pack(side=tk.LEFT, padx=10)
            
            # ========== ФОРМА ==========
            form_frame = tk.LabelFrame(main, text=" Запись ", bg=COLORS["bg"], fg=COLORS["header"], font=("Arial", 10, "bold"))
            form_frame.pack(fill=tk.X, pady=10)
            
            # Поля ввода
            self.site_var = tk.StringVar()
            self.login_var = tk.StringVar()
            self.password_var = tk.StringVar()
            self.password_var.trace_add("write", lambda *_: self._update_strength())
            
            # Сайт
            tk.Label(form_frame, text="Сайт:", bg=COLORS["bg"], fg=COLORS["fg"]).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
            tk.Entry(form_frame, textvariable=self.site_var, width=25, bg=COLORS["entry_bg"], fg=COLORS["fg"]).grid(row=0, column=1, padx=5, pady=5)
            
            # Логин
            tk.Label(form_frame, text="Логин:", bg=COLORS["bg"], fg=COLORS["fg"]).grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
            tk.Entry(form_frame, textvariable=self.login_var, width=25, bg=COLORS["entry_bg"], fg=COLORS["fg"]).grid(row=0, column=3, padx=5, pady=5)
            
            # Пароль
            tk.Label(form_frame, text="Пароль:", bg=COLORS["bg"], fg=COLORS["fg"]).grid(row=0, column=4, sticky=tk.W, padx=5, pady=5)
            tk.Entry(form_frame, textvariable=self.password_var, width=25, show="•", bg=COLORS["entry_bg"], fg=COLORS["fg"]).grid(row=0, column=5, padx=5, pady=5)
            
            # Индикатор надёжности
            strength_frame = tk.Frame(form_frame, bg=COLORS["bg"])
            strength_frame.grid(row=1, column=0, columnspan=6, sticky=tk.W, padx=5, pady=5)
            tk.Label(strength_frame, text="Надёжность:", bg=COLORS["bg"], fg=COLORS["fg"]).pack(side=tk.LEFT)
            self.strength_bar = tk.Canvas(strength_frame, width=200, height=20, bg=COLORS["entry_bg"], highlightthickness=0)
            self.strength_bar.pack(side=tk.LEFT, padx=10)
            self.strength_label = tk.Label(strength_frame, text="—", bg=COLORS["bg"], fg=COLORS["fg"])
            self.strength_label.pack(side=tk.LEFT)
            
            # Рекомендации
            self.recommend_label = tk.Label(form_frame, text="", bg=COLORS["bg"], fg=COLORS["medium"], font=("Arial", 9), wraplength=700, justify=tk.LEFT)
            self.recommend_label.grid(row=2, column=0, columnspan=6, sticky=tk.W, padx=5, pady=5)
            
            # ========== КНОПКИ ==========
            btn_frame1 = tk.Frame(main, bg=COLORS["bg"])
            btn_frame1.pack(fill=tk.X, pady=10)
            
            buttons1 = [
                ("Сохранить", self._save_record),
                ("Редактировать", self._edit_record),
                ("Удалить", self._delete_record),
                ("Показать все", self._show_records),
                ("Копировать пароль", self._copy_password),
                ("Сгенерировать", self._generate_password_dialog),
            ]
            
            for text, cmd in buttons1:
                tk.Button(
                    btn_frame1,
                    text=text,
                    command=cmd,
                    bg=COLORS["button_bg"],
                    fg=COLORS["button_fg"],
                    padx=10,
                    pady=5,
                ).pack(side=tk.LEFT, padx=3)
            
            btn_frame2 = tk.Frame(main, bg=COLORS["bg"])
            btn_frame2.pack(fill=tk.X, pady=5)
            
            buttons2 = [
                ("Резервная копия", self._create_backup),
                ("Восстановить", self._restore_backup),
                ("PDF отчёт", self._export_pdf),
                ("QR-код", self._show_qr_code),
                ("История", self._show_history),
                ("О защите", self._show_protection_info),
            ]
            
            for text, cmd in buttons2:
                tk.Button(
                    btn_frame2,
                    text=text,
                    command=cmd,
                    bg=COLORS["button_bg"],
                    fg=COLORS["button_fg"],
                    padx=10,
                    pady=5,
                ).pack(side=tk.LEFT, padx=3)
            
            # ========== ТАБЛИЦА ==========
            table_frame = tk.Frame(main, bg=COLORS["bg"])
            table_frame.pack(fill=tk.BOTH, expand=True, pady=10)
            
            columns = ("Сайт", "Логин", "Пароль", "Дата создания")
            self.tree = tk.Frame(table_frame, bg=COLORS["tree_bg"])
            self.tree.pack(fill=tk.BOTH, expand=True)
            
            # Используем Listbox вместо Treeview для простоты
            scrollbar = tk.Scrollbar(table_frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            self.listbox = tk.Listbox(
                table_frame,
                bg=COLORS["tree_bg"],
                fg=COLORS["tree_fg"],
                yscrollcommand=scrollbar.set,
                font=("Arial", 9),
                height=10,
            )
            self.listbox.pack(fill=tk.BOTH, expand=True)
            scrollbar.config(command=self.listbox.yview)
            self.listbox.bind("<<ListboxSelect>>", self._on_listbox_select)
            
            # ========== СТАТИСТИКА ==========
            stats_frame = tk.LabelFrame(main, text=" Статистика безопасности ", bg=COLORS["bg"], fg=COLORS["header"], font=("Arial", 10, "bold"))
            stats_frame.pack(fill=tk.X, pady=10)
            
            self.stats_label = tk.Label(stats_frame, text="", bg=COLORS["bg"], fg=COLORS["fg"])
            self.stats_label.pack(anchor=tk.W, padx=5, pady=5)
            
            # Загружаем записи
            self._show_records()
            
            print("DEBUG: _build_main_window() завершено")
            
        except Exception as error:
            print(f"DEBUG: Ошибка в _build_main_window: {error}")
            app_logger.log_error(f"Ошибка построения окна: {error}")
            raise

    def _update_strength(self) -> None:
        """Обновление индикатора надёжности."""
        password = self.password_var.get()
        if not password:
            self.strength_bar.delete("all")
            self.strength_label.config(text="—")
            self.recommend_label.config(text="")
            return
        
        score, level, recommendations = analyze_password_strength(password)
        
        # Рисуем прогресс-бар
        width = (score / 100) * 200
        color_map = {"слабый": COLORS["weak"], "средний": COLORS["medium"], "сильный": COLORS["strong"]}
        color = color_map.get(level, COLORS["fg"])
        
        self.strength_bar.delete("all")
        self.strength_bar.create_rectangle(0, 0, width, 20, fill=color, outline=color)
        
        self.strength_label.config(text=f"{score}/100 — {level}")
        if recommendations:
            self.recommend_label.config(text="Рекомендации: " + "; ".join(recommendations))
        else:
            self.recommend_label.config(text="")

    def _refresh_listbox(self, indexed_records: list[tuple[int, dict]]) -> None:
        """Обновление списка."""
        self.listbox.delete(0, tk.END)
        for storage_index, record in indexed_records:
            line = f"{record['site']:20} | {record['login']:20} | {record['created_at']}"
            self.listbox.insert(tk.END, line)
            self.listbox.itemconfig(tk.END, {"bg": COLORS["tree_bg"]})
        
        records = [record for _, record in indexed_records]
        self._update_statistics(records)

    def _update_statistics(self, records: list[dict]) -> None:
        """Обновление статистики."""
        stats = compute_statistics(records)
        text = (
            f"Всего: {stats['total']}  |  "
            f"Ср. длина: {stats['avg_length']}  |  "
            f"Сильных: {stats['strong_count']} ({stats['strong_percent']}%)"
        )
        self.stats_label.config(text=text)

    def _on_search(self) -> None:
        """Поиск."""
        query = self.search_var.get()
        indexed = pwd_manager.search_by_site(query)
        self._refresh_listbox(indexed)

    def _on_listbox_select(self, _event: Any = None) -> None:
        """Выбор записи."""
        try:
            selection = self.listbox.curselection()
            if not selection:
                return
            
            idx = selection[0]
            records = pwd_manager.get_records()
            
            # Найдём индекс оригинальной записи
            query = self.search_var.get()
            indexed = pwd_manager.search_by_site(query)
            
            if idx < len(indexed):
                storage_index, record = indexed[idx]
                self.site_var.set(record["site"])
                self.login_var.set(record["login"])
                self.password_var.set(record["password"])
        except Exception as error:
            app_logger.log_error(f"Ошибка выбора: {error}")

    def _clear_form(self) -> None:
        """Очистка формы."""
        self.site_var.set("")
        self.login_var.set("")
        self.password_var.set("")

    def _save_record(self) -> None:
        """Сохранение записи."""
        try:
            success, msg = pwd_manager.add_record(
                self.site_var.get(),
                self.login_var.get(),
                self.password_var.get(),
            )
            if success:
                messagebox.showinfo("Успех", "Запись сохранена")
                self._clear_form()
                self._on_search()
            else:
                messagebox.showwarning("Ошибка", msg)
        except Exception as error:
            app_logger.log_error(f"Ошибка сохранения: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _edit_record(self) -> None:
        """Редактирование."""
        try:
            query = self.search_var.get()
            indexed = pwd_manager.search_by_site(query)
            selection = self.listbox.curselection()
            
            if not selection:
                messagebox.showwarning("Внимание", "Выберите запись")
                return
            
            idx = selection[0]
            if idx < len(indexed):
                storage_index, _ = indexed[idx]
                success, msg = pwd_manager.update_record(
                    storage_index,
                    self.site_var.get(),
                    self.login_var.get(),
                    self.password_var.get(),
                )
                if success:
                    messagebox.showinfo("Успех", "Запись обновлена")
                    self._on_search()
                else:
                    messagebox.showwarning("Ошибка", msg)
        except Exception as error:
            app_logger.log_error(f"Ошибка редактирования: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _delete_record(self) -> None:
        """Удаление."""
        try:
            query = self.search_var.get()
            indexed = pwd_manager.search_by_site(query)
            selection = self.listbox.curselection()
            
            if not selection:
                messagebox.showwarning("Внимание", "Выберите запись")
                return
            
            if not messagebox.askyesno("Подтверждение", "Удалить запись?"):
                return
            
            idx = selection[0]
            if idx < len(indexed):
                storage_index, _ = indexed[idx]
                success, msg = pwd_manager.delete_record(storage_index)
                if success:
                    messagebox.showinfo("Успех", "Запись удалена")
                    self._clear_form()
                    self._on_search()
                else:
                    messagebox.showwarning("Ошибка", msg)
        except Exception as error:
            app_logger.log_error(f"Ошибка удаления: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _show_records(self) -> None:
        """Показать все записи."""
        try:
            pwd_manager.load_records()
            self.search_var.set("")
            indexed = list(enumerate(pwd_manager.get_records()))
            self._refresh_listbox(indexed)
        except Exception as error:
            app_logger.log_error(f"Ошибка загрузки: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _copy_password(self) -> None:
        """Копирование пароля."""
        try:
            password = self.password_var.get()
            if not password:
                messagebox.showwarning("Внимание", "Нет пароля")
                return
            pyperclip.copy(password)
            messagebox.showinfo("Успех", "Пароль скопирован")
        except Exception as error:
            app_logger.log_error(f"Ошибка копирования: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _generate_password_dialog(self) -> None:
        """Генератор паролей."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Генератор паролей")
        dialog.geometry("380x300")
        dialog.configure(bg=COLORS["bg"])

        frame = tk.Frame(dialog, bg=COLORS["bg"])
        frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        tk.Label(frame, text="Генератор паролей", font=("Arial", 12, "bold"), bg=COLORS["bg"], fg=COLORS["header"]).pack(pady=(0, 10))

        length_var = tk.IntVar(value=16)
        tk.Label(frame, text="Длина (12–20):", bg=COLORS["bg"], fg=COLORS["fg"]).pack(anchor=tk.W)
        tk.Scale(frame, from_=12, to=20, orient=tk.HORIZONTAL, variable=length_var, bg=COLORS["button_bg"], fg=COLORS["button_fg"]).pack(fill=tk.X, pady=5)

        lower_var = tk.BooleanVar(value=True)
        upper_var = tk.BooleanVar(value=True)
        digits_var = tk.BooleanVar(value=True)
        special_var = tk.BooleanVar(value=True)

        for text, var in [
            ("Строчные буквы", lower_var),
            ("Заглавные буквы", upper_var),
            ("Цифры", digits_var),
            ("Спецсимволы", special_var),
        ]:
            tk.Checkbutton(frame, text=text, variable=var, bg=COLORS["bg"], fg=COLORS["fg"], selectcolor=COLORS["button_bg"]).pack(anchor=tk.W)

        result_var = tk.StringVar()

        def do_generate() -> None:
            pwd = generate_password(
                length=int(length_var.get()),
                use_lower=lower_var.get(),
                use_upper=upper_var.get(),
                use_digits=digits_var.get(),
                use_special=special_var.get(),
            )
            result_var.set(pwd)

        tk.Button(frame, text="Сгенерировать", command=do_generate, bg=COLORS["button_bg"], fg=COLORS["button_fg"], padx=15, pady=5).pack(pady=8)
        tk.Entry(frame, textvariable=result_var, width=40, bg=COLORS["entry_bg"], fg=COLORS["fg"]).pack(pady=5)

        def insert() -> None:
            if result_var.get():
                self.password_var.set(result_var.get())
                dialog.destroy()

        tk.Button(frame, text="Вставить", command=insert, bg=COLORS["button_bg"], fg=COLORS["button_fg"], padx=15, pady=5).pack()
        do_generate()

    def _create_backup(self) -> None:
        """Резервная копия."""
        try:
            success, msg = backup_manager.create_backup()
            messagebox.showinfo("Успех" if success else "Ошибка", msg)
        except Exception as error:
            app_logger.log_error(f"Ошибка backup: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _restore_backup(self) -> None:
        """Восстановление."""
        try:
            filepath = filedialog.askopenfilename(title="Выберите backup", filetypes=[("JSON", "*.json")])
            if not filepath or not messagebox.askyesno("Подтверждение", "Восстановить?"):
                return
            success, msg = backup_manager.restore_backup(filepath)
            if success:
                pwd_manager.load_records()
                self._on_search()
            messagebox.showinfo("Успех" if success else "Ошибка", msg)
        except Exception as error:
            app_logger.log_error(f"Ошибка restore: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _export_pdf(self) -> None:
        """Экспорт PDF."""
        try:
            from datetime import datetime
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen import canvas

            os.makedirs(EXPORTS_DIR, exist_ok=True)
            records = pwd_manager.get_records()
            stats = compute_statistics(records)
            
            filepath = os.path.join(EXPORTS_DIR, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
            pdf = canvas.Canvas(filepath, pagesize=A4)
            width, height = A4
            y = height - 50

            pdf.setFont("Helvetica-Bold", 16)
            pdf.drawString(50, y, "Отчёт — Менеджер паролей")
            y -= 30

            pdf.setFont("Helvetica", 10)
            pdf.drawString(50, y, f"Записей: {stats['total']} | Ср. длина: {stats['avg_length']} | Сильных: {stats['strong_percent']}%")
            y -= 20

            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawString(50, y, "Сайты:")
            y -= 15

            pdf.setFont("Helvetica", 9)
            for record in records:
                if y < 60:
                    pdf.showPage()
                    y = height - 50
                pdf.drawString(60, y, f"• {record['site']} — {record['created_at']}")
                y -= 12

            pdf.save()
            messagebox.showinfo("Успех", f"Сохранено: {filepath}")
        except Exception as error:
            app_logger.log_error(f"Ошибка PDF: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _show_qr_code(self) -> None:
        """QR-код."""
        try:
            selection = self.listbox.curselection()
            if not selection:
                messagebox.showwarning("Внимание", "Выберите запись")
                return

            site = self.site_var.get()
            qr_data = f"SITE:{site}\nLOGIN:{self.login_var.get()}\nPASS:{self.password_var.get()}"

            os.makedirs(EXPORTS_DIR, exist_ok=True)
            from datetime import datetime
            filepath = os.path.join(EXPORTS_DIR, f"qr_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")

            if not save_qr_code(qr_data, filepath):
                messagebox.showerror("Ошибка", "Не удалось создать QR")
                return

            try:
                from PIL import Image, ImageTk
                qr_window = tk.Toplevel(self.root)
                qr_window.title(f"QR-код — {site}")
                qr_window.configure(bg=COLORS["bg"])

                img = Image.open(filepath)
                img = img.resize((250, 250), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)

                label = tk.Label(qr_window, image=photo, bg=COLORS["bg"])
                label.image = photo
                label.pack(pady=15)
            except ImportError:
                messagebox.showinfo("QR создан", f"Сохранено: {filepath}")
        except Exception as error:
            app_logger.log_error(f"Ошибка QR: {error}")
            messagebox.showerror("Ошибка", str(error))

    def _show_history(self) -> None:
        """История действий."""
        try:
            window = tk.Toplevel(self.root)
            window.title("История")
            window.geometry("700x450")
            window.configure(bg=COLORS["bg"])

            frame = tk.Frame(window, bg=COLORS["bg"])
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            tk.Label(frame, text="История действий", font=("Arial", 12, "bold"), bg=COLORS["bg"], fg=COLORS["header"]).pack()

            text = tk.Text(frame, bg=COLORS["entry_bg"], fg=COLORS["fg"], font=("Courier", 9), wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True, pady=10)

            entries = app_logger.get_recent_entries(100)
            text.insert(tk.END, "\n".join(entries) if entries else "Журнал пуст")
            text.config(state=tk.DISABLED)
        except Exception as error:
            app_logger.log_error(f"Ошибка истории: {error}")

    def _show_protection_info(self) -> None:
        """О защите информации."""
        try:
            window = tk.Toplevel(self.root)
            window.title("О защите информации")
            window.geometry("620x520")
            window.configure(bg=COLORS["bg"])

            frame = tk.Frame(window, bg=COLORS["bg"])
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            tk.Label(frame, text="Виды защиты информации", font=("Arial", 12, "bold"), bg=COLORS["bg"], fg=COLORS["header"]).pack()

            text = tk.Text(frame, bg=COLORS["entry_bg"], fg=COLORS["fg"], font=("Arial", 9), wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True, pady=10)

            info = """ВИДЫ ЗАЩИТЫ ИНФОРМАЦИИ

1. Физическая защита
   Охрана помещений, сейфы, контроль доступа.

2. Программная защита
   Шифрование (Fernet/AES), аутентификация (SHA-256).

3. Аппаратная защита
   TPM-модули, HSM, биометрия.

4. Организационная защита
   Политики, разграничение прав.

5. Законодательная защита
   ФЗ «О персональных данных», GDPR.

6. Психологическая защита
   Осведомлённость, противодействие социнженерии.

РЕАЛИЗОВАНО В ПРИЛОЖЕНИИ:
✓ SHA-256 хеширование мастер-пароля
✓ Fernet шифрование данных
✓ Защита от перебора (блокировка на 30 сек)
✓ Автоблокировка после 5 минут
✓ Журналирование всех действий
✓ Резервное копирование"""

            text.insert(tk.END, info)
            text.config(state=tk.DISABLED)
        except Exception as error:
            app_logger.log_error(f"Ошибка info: {error}")


def main() -> None:
    """Главная функция."""
    print("\n" + "=" * 80)
    print("ЗАПУСК МЕНЕДЖЕРА ПАРОЛЕЙ")
    print("=" * 80 + "\n")

    try:
        print("DEBUG: Создание объекта приложения...")
        app = PasswordManagerApp()
        print("DEBUG: Объект создан успешно, запуск...")
        app.run()
        print("\nDEBUG: Приложение завершено\n")

    except Exception as error:
        print(f"\nERROR: {error}\n")
        app_logger.log_error(f"Критическая ошибка: {error}")
        import traceback
        print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
