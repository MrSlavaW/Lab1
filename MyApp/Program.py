import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel, ttk
import json
import os
import hashlib
import re

# Константи та Управління Даними Користувачів
USER_DATA_FILE = 'users.json'
ADMIN_USERNAME = 'ADMIN'
MAX_LOGIN_ATTEMPTS = 3


class UserManager:
    # Керує читанням, записом та логікою користувачів

    @staticmethod
    def _hash_password(password):
        # Хешує пароль за допомогою SHA-256 для безпечного зберігання
        return hashlib.sha256(password.encode()).hexdigest()

    def load_users(self):
        # Завантажує дані користувачів з файлу або створює файл адміністратора, якщо він відсутній
        if not os.path.exists(USER_DATA_FILE):
            # Створення початкового файлу з адміністратором
            initial_data = {
                ADMIN_USERNAME: {
                    'password': self._hash_password(""),  # Хеш порожнього пароля
                    'is_admin': True,
                    'is_blocked': False,
                    'restrictions_on': False,
                    'first_login': True  # Вимагати зміну пароля при першому вході
                }
            }
            try:
                with open(USER_DATA_FILE, 'w', encoding='utf-8') as f:
                    json.dump(initial_data, f, indent=4)
            except IOError as e:
                messagebox.showerror("Помилка Файлової Системи", f"Не вдалося створити файл {USER_DATA_FILE}: {e}")
                return {}

        try:
            with open(USER_DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            messagebox.showerror("Помилка Файлу", f"Помилка читання JSON у файлі {USER_DATA_FILE}. Файл пошкоджений.")
            return {}
        except IOError as e:
            messagebox.showerror("Помилка Файлової Системи", f"Помилка читання файлу {USER_DATA_FILE}: {e}")
            return {}

    def save_users(self, users):
        # Зберігає поточні дані користувачів у файл
        try:
            with open(USER_DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(users, f, indent=4)
        except IOError as e:
            messagebox.showerror("Помилка Збереження", f"Не вдалося зберегти дані користувачів: {e}")

    def verify_password(self, username, password):
        # Перевіряє, чи відповідає введений пароль збереженому хешу
        users = self.load_users()
        if username not in users:
            return False

        hashed_input = self._hash_password(password)
        return users[username]['password'] == hashed_input

    def update_password(self, username, new_password):
        # Оновлює пароль користувача та скидає прапорець першого входу
        users = self.load_users()
        users[username]['password'] = self._hash_password(new_password)
        users[username]['first_login'] = False
        self.save_users(users)

    def add_user(self, username):
        # Додає нового користувача з порожнім паролем
        users = self.load_users()
        if username in users:
            return False

        users[username] = {
            'password': self._hash_password(""),  # Хеш порожнього пароля
            'is_admin': False,
            'is_blocked': False,
            'restrictions_on': False,
            'first_login': True
        }
        self.save_users(users)
        return True

    def toggle_user_status(self, username, status_key, value=None):
        #Перемикає статус користувача
        users = self.load_users()
        if username in users and not users[username]['is_admin']:
            if value is not None:
                users[username][status_key] = value
            else:
                users[username][status_key] = not users[username][status_key]
            self.save_users(users)
            return True
        return False

    def check_password_restrictions(self, password):
        """
        Перевіряє пароль відповідно до індивідуального завдання (Варіант 6).
        Завдання: Наявність літер і знаків арифметичних операцій (+, -, *, /).
        """
        if len(password) < 1:
            return False

        has_letter = bool(re.search(r'[a-zA-Zа-яА-Я]', password))
        has_arithmetic_sign = bool(re.search(r'[+\-*/]', password))

        return has_letter and has_arithmetic_sign


# Вікно Входу та Основна Програма

class AuthSystemApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Система Аутентифікації")
        self.user_manager = UserManager()
        self.current_user = None
        self.login_attempts = 0
        self.users = self.user_manager.load_users()

        self.withdraw()  # Приховуємо головне вікно до успішного входу
        self.show_login_window()

        self.protocol("WM_DELETE_WINDOW", self.quit)  # Обробка закриття головного вікна

    def show_login_window(self):
        # Відображає діалогове вікно входу
        self.login_window = Toplevel(self)
        self.login_window.title("Вхід до Системи")
        self.login_window.geometry("300x180")
        # Якщо закрити вікно входу, програма завершується
        self.login_window.protocol("WM_DELETE_WINDOW", self.quit)

        # UI елементи
        tk.Label(self.login_window, text="Ім'я користувача:", font=('Arial', 10)).pack(pady=(10, 2))
        self.username_entry = tk.Entry(self.login_window, font=('Arial', 10), width=30)
        self.username_entry.pack(pady=2)

        tk.Label(self.login_window, text="Пароль:", font=('Arial', 10)).pack(pady=(5, 2))
        self.password_entry = tk.Entry(self.login_window, show="*", font=('Arial', 10), width=30)
        self.password_entry.pack(pady=2)

        tk.Button(self.login_window, text="Увійти", command=self.attempt_login, bg='#4CAF50', fg='white',
                  relief=tk.RAISED).pack(pady=10)

        # Центрування вікна
        self.login_window.update_idletasks()
        width = self.login_window.winfo_width()
        height = self.login_window.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.login_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        self.login_window.grab_set()  # Робить вікно модальним

    def attempt_login(self):
        # Обробка спроби входу
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if not username:
            messagebox.showerror("Помилка", "Введіть ім'я користувача.", parent=self.login_window)
            return

        self.users = self.user_manager.load_users()

        if username not in self.users:
            messagebox.showerror("Помилка", f"Користувача '{username}' не знайдено.", parent=self.login_window)
            self.reset_login_form()
            return

        if self.users[username]['is_blocked']:
            messagebox.showerror("Блокування", f"Обліковий запис '{username}' заблоковано адміністратором.",
                                 parent=self.login_window)
            self.reset_login_form()
            return

        if self.user_manager.verify_password(username, password):
            # Успішний Вхід
            self.current_user = username
            self.login_window.destroy()
            self.login_attempts = 0
            self.show_main_interface()
        else:
            # Неправильний Пароль
            self.login_attempts += 1
            messagebox.showerror("Помилка", "Неправильний пароль. Спроба "
                                            f"{self.login_attempts} з {MAX_LOGIN_ATTEMPTS}.", parent=self.login_window)
            self.password_entry.delete(0, tk.END)

            if self.login_attempts >= MAX_LOGIN_ATTEMPTS:
                messagebox.showerror("Помилка",
                                     f"Використано {MAX_LOGIN_ATTEMPTS} спроб. Робота програми завершується.",
                                     parent=self.login_window)
                self.quit()

    def reset_login_form(self):
        # Очищає форму входу
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def show_main_interface(self):
        # Налаштовує головне вікно після успішного входу
        self.title(f"Система Аутентифікації - Користувач: {self.current_user}")
        self.geometry("800x100")
        self.deiconify()  # Показати головне вікно

        self.is_admin = self.users[self.current_user]['is_admin']

        self._setup_menu()
        self._setup_toolbar()
        self._setup_statusbar()
        self._check_first_login()

    def _check_first_login(self):
        # Перевірка, чи потрібна зміна пароля при першому вході
        self.users = self.user_manager.load_users()
        if self.users.get(self.current_user, {}).get('first_login', False):
            messagebox.showinfo("Перший Вхід", "Це Ваш перший вхід. Ви повинні встановити новий пароль.")
            self.change_password(is_first_login=True)

    def _setup_menu(self):
        #Налаштовує панель меню
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # Меню
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Змінити Пароль", command=self.change_password)
        file_menu.add_separator()
        file_menu.add_command(label="Завершити Роботу", command=self.quit)

        # Меню Адміністрування
        if self.is_admin:
            admin_menu = tk.Menu(menubar, tearoff=0)
            menubar.add_cascade(label="Адміністрування", menu=admin_menu)
            admin_menu.add_command(label="Додати Користувача", command=self.admin_add_user)
            admin_menu.add_command(label="Переглянути/Керувати Користувачами", command=self.admin_view_users)
            # Примітка: Блокування та Обмеження тепер керуються через admin_view_users

        # Меню Довідка
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Довідка", menu=help_menu)
        help_menu.add_command(label="Про програму", command=self.show_about)

    def _setup_toolbar(self):
        # Панель керування
        toolbar = tk.Frame(self, bd=1, relief=tk.RAISED, bg='#f0f0f0')

        tk.Button(toolbar, text="Змінити Пароль", command=self.change_password).pack(side=tk.LEFT, padx=5, pady=2)

        if self.is_admin:
            tk.Button(toolbar, text="Додати Користувача", command=self.admin_add_user).pack(side=tk.LEFT, padx=5,
                                                                                              pady=2)
            tk.Button(toolbar, text="Керування Користувачами", command=self.admin_view_users).pack(side=tk.LEFT,
                                                                                                     padx=5, pady=2)

        tk.Button(toolbar, text="Вихід", command=self.quit, bg='#dc3545', fg='white').pack(side=tk.RIGHT, padx=5,
                                                                                             pady=2)

        toolbar.pack(side=tk.TOP, fill=tk.X)

    def _setup_statusbar(self):
        # Рядок стану
        status_text = f"Режим: {'Адміністратор' if self.is_admin else 'Користувач'} | Поточний Користувач: {self.current_user}"
        self.status_bar = tk.Label(self, text=status_text, bd=1, relief=tk.SUNKEN, anchor=tk.W, font=('Arial', 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # Функції Користувача

    def change_password(self, is_first_login=False):
        # Обробляє зміну пароля

        # 1. Запит старого пароля (якщо це не перший вхід)
        if not is_first_login:
            old_password = simpledialog.askstring("Зміна Пароля", "Введіть старий пароль:", show='*')
            if not old_password:
                return

            if not self.user_manager.verify_password(self.current_user, old_password):
                messagebox.showerror("Помилка", "Неправильний старий пароль.")
                return

        while True:
            # 2. Запит нового пароля та його підтвердження
            new_password = simpledialog.askstring("Зміна Пароля", "Введіть новий пароль:", show='*')
            if new_password is None:  # Натиснуто 'Скасувати'
                if is_first_login:
                    # При першому вході відмова = завершення роботи
                    if messagebox.askyesno("Відмова", "Ви повинні встановити пароль. Завершити роботу?"):
                        self.quit()
                    return  # Повторити
                messagebox.showinfo("Скасовано", "Зміну пароля скасовано.")
                return

            confirm_password = simpledialog.askstring("Підтвердження Пароля", "Повторіть новий пароль:", show='*')

            if new_password != confirm_password:
                messagebox.showerror("Помилка", "Паролі не співпадають. Спробуйте ще раз.")
                continue

            # 3. Перевірка обмежень
            self.users = self.user_manager.load_users()
            user_data = self.users.get(self.current_user, {})

            if user_data.get('restrictions_on', False):
                if not self.user_manager.check_password_restrictions(new_password):
                    # Пароль не відповідає обмеженням
                    restriction_info = "Пароль повинен містити:\n1. Хоча б одну літеру (латинську або кирилицю).\n2. Хоча б один знак арифметичної операції (+, -, *, /)."

                    # Перевірка на випадок, якщо це перший вхід
                    if is_first_login:
                        if not messagebox.askyesno("Обмеження Пароля",
                                                   f"Пароль не відповідає вимогам:\n\n{restriction_info}\n\nСпробувати інший пароль? (Ні = Вихід)"):
                            self.quit()
                    else:
                        messagebox.showwarning("Обмеження Пароля",
                                               f"Пароль не відповідає вимогам:\n\n{restriction_info}")
                        if not messagebox.askyesno("Обмеження", "Спробувати інший пароль? (Ні = Скасувати Зміну)"):
                            return
                    continue  # Повторити цикл запиту пароля

            # 4. Зміна пароля успішна
            self.user_manager.update_password(self.current_user, new_password)
            messagebox.showinfo("Успіх", "Пароль успішно змінено.")
            return

    # Функції Адміністратора

    def admin_add_user(self):
        #Додає нового користувача з порожнім паролем
        username = simpledialog.askstring("Додати Користувача", "Введіть унікальне ім'я нового користувача:")
        if not username:
            return

        username = username.strip()
        if not username or username == ADMIN_USERNAME:
            messagebox.showerror("Помилка", f"Недійсне ім'я користувача.")
            return

        if self.user_manager.add_user(username):
            messagebox.showinfo("Успіх", f"Користувача '{username}' успішно додано. Пароль порожній.")
        else:
            messagebox.showerror("Помилка", f"Користувач з іменем '{username}' вже існує.")

    def admin_view_users(self):
        #Відображає список користувачів та статусів

        view_window = Toplevel(self)
        view_window.title("Керування Користувачами")
        view_window.geometry("650x400")

        # Відображення списку
        tree = ttk.Treeview(view_window, columns=('Username', 'Admin', 'Blocked', 'Restrictions', 'First Login'),show='headings')
        tree.heading('Username', text="Ім'я Користувача")
        tree.heading('Admin', text='Адмін')
        tree.heading('Blocked', text='Блок')
        tree.heading('Restrictions', text='Обмеж.')
        tree.heading('First Login', text='Перший вхід')

        tree.column('Username', width=150, anchor=tk.W)
        tree.column('Admin', width=70, anchor=tk.CENTER)
        tree.column('Blocked', width=70, anchor=tk.CENTER)
        tree.column('Restrictions', width=80, anchor=tk.CENTER)
        tree.column('First Login', width=90, anchor=tk.CENTER)

        # Функція оновлення списку
        def populate_tree():
            self.users = self.user_manager.load_users()
            for item in tree.get_children():
                tree.delete(item)

            for username, data in self.users.items():
                tree.insert('', tk.END, iid=username,  # Використовуємо ім'я як ID елемента
                            values=(
                                username,
                                'Так' if data['is_admin'] else 'Ні',
                                'Так' if data['is_blocked'] else 'Ні',
                                'Так' if data['restrictions_on'] else 'Ні',
                                'Так' if data['first_login'] else 'Ні'
                            ),
                            tags=('blocked' if data['is_blocked'] else 'active',)
                            )
            tree.tag_configure('blocked', background='#f79999')  # Блідо-червоний для заблокованих
            tree.tag_configure('active', background='#ffffff')

        # Функції керування (викликаються після вибору користувача)
        def toggle_status(status_key):
            try:
                selected_user = tree.selection()[0]
            except IndexError:
                messagebox.showerror("Помилка", "Будь ласка, виберіть користувача.")
                return

            if selected_user == ADMIN_USERNAME:
                messagebox.showwarning("Помилка", "Неможливо змінити статус адміністратора.")
                return

            if self.user_manager.toggle_user_status(selected_user, status_key):
                populate_tree()  # Оновити список
                status_name = "Блокування" if status_key == 'is_blocked' else "Обмеження Пароля"
                action = "увімкнено" if self.users[selected_user][status_key] else "вимкнено"
                messagebox.showinfo("Успіх", f"Для '{selected_user}' статус '{status_name}' {action}.")
            else:
                messagebox.showerror("Помилка", "Помилка при зміні статусу.")

        # Налаштування кнопок керування
        control_frame = tk.Frame(view_window)
        control_frame.pack(pady=10)

        tk.Button(control_frame, text="Блокувати/Розблокувати", command=lambda: toggle_status('is_blocked')).pack(
            side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Обмеження Пароля", command=lambda: toggle_status('restrictions_on')).pack(
            side=tk.LEFT, padx=5)

        # Відображення списку
        scrollbar = ttk.Scrollbar(view_window, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        populate_tree()
        view_window.grab_set()

    # Функції Довідки

    def show_about(self):
        # Відображає інформацію про автора та завдання
        about_text = (
            "**Система Парольної Ідентифікації/Аутентифікації**\n"
            "---------------------------------------------------\n"
            "Розроблено у відповідності до вимог практичної роботи №1.\n"
            "\n"
            "**Інтерфейс:** Tkinter (Python).\n"
            "**Безпека:** Паролі зберігаються у хешованому вигляді (SHA-256).\n"
            "**Керування:** Облікові записи ADMIN та звичайні користувачі, функціонал блокування та обмежень.\n"
            "\n"
            "**Індивідуальне Завдання (Варіант 6):**\n"
            "Пароль повинен містити **літери** та **знаки арифметичних операцій** (+, -, *, /)."
        )
        messagebox.showinfo("Про програму", about_text)

if __name__ == '__main__':
    # Перевірка та ініціалізація даних перед запуском
    UserManager().load_users()

    app = AuthSystemApp()
    app.mainloop()