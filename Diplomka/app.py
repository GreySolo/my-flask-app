from enum import Enum
from flask import Flask, logging, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_apscheduler import APScheduler
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
from datetime import datetime, timedelta
import mysql.connector
import re, os, uuid
from config import Config

# Инициализация приложения
db = SQLAlchemy()  # ← создаем БЕЗ app
migrate = Migrate()
login_manager = LoginManager()
scheduler = APScheduler()

app = Flask(__name__)

# Конфигурация
app.config.update(
    SQLALCHEMY_DATABASE_URI='mysql+pymysql://root:@localhost/diplomka',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SECRET_KEY='logrey',
    UPLOAD_FOLDER='static/uploads',
    ALLOWED_EXTENSIONS={'png', 'jpg', 'jpeg', 'gif'},
    SCHEDULER_API_ENABLED=True
)

# Инициализация расширений
db.init_app(app)
migrate.init_app(app, db)
login_manager.init_app(app)
scheduler.init_app(app)
scheduler.start()

project_user_association = db.Table(
    'project_user_association',
    db.Column('project_id', db.Integer, db.ForeignKey('projects.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)

# ------------------- Утилиты -------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='diplomka'
    )

# ------------------- Модели -------------------

# Пользователь
from flask_login import UserMixin  # Импортируем UserMixin

# Пользователь
class User(db.Model, UserMixin):  # Наследуемся от UserMixin
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), default='user', nullable=False)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    middle_name = db.Column(db.String(50), nullable=True)
    image_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Связь с заявками
    requests = db.relationship('Request', back_populates='user', lazy=True)
    
    notifications = db.relationship(
        'Notification',
        back_populates='user',
        lazy=True,
        primaryjoin='User.id == Notification.user_id'
    )
    projects = db.relationship('Project', back_populates='user', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @property
    def full_name(self):
        return f"{self.last_name or ''} {self.first_name or ''} {self.middle_name or ''}".strip()

    @property
    def is_admin(self):
        return self.role == 'admin'
    
# Проекты, к которым пользователь прикреплён (как исполнитель)
    assigned_projects = db.relationship(
        'Project',
        secondary=project_user_association,
        back_populates='assigned_users',
        lazy='subquery'
    )

# Проекты
class Project(db.Model):
    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default='active')  # <-- ДОБАВЛЕНО

    # Внешний ключ, который связывает проект с пользователем
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', back_populates='projects', lazy=True)
    
    # Назначенные пользователи (исполнители)
    assigned_users = db.relationship(
        'User',
        secondary=project_user_association,
        back_populates='assigned_projects',
        lazy='subquery'
    )

#Заявки
class StatusEnum(Enum):
    NEW = "Новая"
    IN_PROGRESS = "В обработке"
    APPROVED = "Одобрена"
    REJECTED = "Отклонена"

class Request(db.Model):
    __tablename__ = 'requests'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)  # Обязательное поле
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.Enum(StatusEnum), nullable=False, default=StatusEnum.NEW, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Дополнительные поля для заявок
    documents = db.Column(db.Text, nullable=True)
    material_details = db.Column(db.Text, nullable=True)
    equipment_details = db.Column(db.Text, nullable=True)
    vacation_reason = db.Column(db.String(255), nullable=True)
    vacation_dates = db.Column(db.Date, nullable=True)  # Для даты отпуска
    tools_needed = db.Column(db.Text, nullable=True)
    training_details = db.Column(db.Text, nullable=True)
    equipment_issue = db.Column(db.Text, nullable=True)
    new_working_hours = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Для отслеживания обновлений

    # Связь с пользователем
    user = db.relationship('User', back_populates='requests')

    def __repr__(self):
        return f"<Request {self.title}>"

# Уведомления
class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    user = db.relationship('User', back_populates='notifications')

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # <-- внеш. ключ
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    object_type = db.Column(db.String(50))
    object_id = db.Column(db.Integer)

    # отношение к пользователю
    user = db.relationship('User', backref='logs')

    def __repr__(self):
        return f'<Log {self.id}>'

# Загрузка пользователя по ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------- Маршруты -------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone_number = request.form.get('phone_number', '').strip()
        password = request.form.get('password', '').strip()

        # Проверка на пустой номер телефона
        if not phone_number:
            flash('Номер телефона обязателен для входа', 'danger')
            return redirect(url_for('login'))

        # Проверка формата номера телефона
        if not validate_phone_number(phone_number):
            flash('Неверный формат номера телефона. Используйте формат: +79991234567 или 89991234567', 'danger')
            return redirect(url_for('login'))

        # Поиск пользователя по номеру телефона
        user = User.query.filter_by(phone_number=phone_number).first()

        if not user:
            flash('Пользователь с таким номером телефона не найден', 'danger')
            return redirect(url_for('login'))

        if not user.check_password(password):
            flash('Неверный пароль', 'danger')
            return redirect(url_for('login'))

        # Авторизация пользователя
        login_user(user)
        flash('Вы успешно вошли!', 'success')
        return redirect(url_for('profile'))

    return render_template('login.html')

def validate_phone_number(phone_number):
    # Убираем все нецифровые символы для проверки
    digits_only = re.sub(r'\D', '', phone_number)
    
    # Проверяем, что номер начинается с 7 или 8 и содержит ровно 11 цифр
    if digits_only.startswith('7'):
        return len(digits_only) == 11
    
    return False

@app.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT title, description, is_primary, image_url FROM activities ORDER BY is_primary DESC, id')
    activities = cursor.fetchall()
    print(activities)  # Выводим данные в консоль для отладки
    cursor.close()
    conn.close()
    return render_template('index.html', activities=activities)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/upload_image', methods=['POST'])
def upload_image():
    file = request.files.get('image')
    if not file or file.filename == '':
        return "Файл не выбран", 400
    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'message': 'Image uploaded successfully', 'filename': filename}), 201
    return "Недопустимый формат файла", 400

# Профиль пользователя
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        new_password = request.form.get('new_password', '').strip()
        profile_image = request.files.get('profile_image')

        if email:
            current_user.email = email
        if new_password:
            current_user.set_password(new_password)

        if profile_image and profile_image.filename and allowed_file(profile_image.filename):
            filename = secure_filename(profile_image.filename)
            if filename:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_image.save(filepath)
                current_user.image_url = filename

        db.session.commit()
        flash('Профиль обновлён', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')

# Уведомления
@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    return render_template('notifications.html', notifications=notifications)

def create_notification(user_id, message):
    new_notification = Notification(user_id=user_id, message=message)
    db.session.add(new_notification)
    db.session.commit()

@app.route('/notifications/mark_as_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_as_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()
    return redirect(url_for('notifications'))

# Непрочитанные уведомления
@app.context_processor
def inject_unread_notifications():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return {'unread_notifications': unread_count}
    return {}

@app.route('/logout')
def logout():
    logout_user()
    flash('Вы вышли из системы', 'success')
    return redirect(url_for('login'))

# Смена пароля
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT password FROM users WHERE id=%s", (current_user.id,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], current_password):
            new_hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password=%s WHERE id=%s", (new_hashed_password, current_user.id))
            conn.commit()
            flash('Пароль успешно изменен', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Неверный текущий пароль', 'danger')

        cursor.close()
        conn.close()

    return render_template('change_password.html')

# Панель администратора
@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Заявки с привязкой к пользователям
    cursor.execute("""
        SELECT requests.*, users.first_name, users.last_name, users.middle_name 
        FROM requests 
        JOIN users ON requests.user_id = users.id
        ORDER BY requests.created_at DESC
    """)
    requests = cursor.fetchall()

    # Пользователи
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    # Логи
    cursor.execute("""
        SELECT logs.id, logs.action, logs.timestamp
        FROM logs 
        JOIN users ON logs.user_id = users.id
        ORDER BY logs.timestamp DESC
    """)
    logs = cursor.fetchall()

    # Проекты
    cursor.execute("SELECT * FROM projects ORDER BY created_at DESC")
    projects = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin.html', requests=requests, users=users, logs=logs, projects=projects)

@app.route('/view_requests')
@login_required
def view_requests():
    try:
        conn = get_db_connection()
        with conn.cursor(dictionary=True) as cursor:
            cursor.execute("SELECT * FROM requests WHERE user_id = %s", (current_user.id,))
            requests = cursor.fetchall()
    except Exception as e:
        flash(f"Ошибка при загрузке заявок: {str(e)}", 'danger')
        return redirect(url_for('index'))  # Перенаправление на главную страницу при ошибке
    finally:
        conn.close()

    # Передаем заявки в шаблон
    return render_template('view_requests.html', requests=requests)

@app.route('/add_request', methods=['GET', 'POST'])
@login_required
def add_request():
    if request.method == 'POST':
        request_type = request.form.get('request_type')
        title = request.form.get('title') or ''
        description = request.form.get('description') or ''

        # В зависимости от типа, дополняем описание
        if request_type == 'Запрос на документы':
            description = request.form.get('documents')
        elif request_type == 'Запрос на материалы':
            description = request.form.get('material_details')
        elif request_type == 'Запрос на рабочее оборудование':
            description = request.form.get('equipment_details')
        elif request_type == 'Заявка на отпуск':
            description = f"Причина: {request.form.get('vacation_reason')}, Даты: {request.form.get('vacation_dates')}"
        elif request_type == 'Заявка на смену рабочего времени':
            description = request.form.get('new_working_hours')
        elif request_type == 'Запрос на рабочие инструменты':
            description = request.form.get('tools_needed')
        elif request_type == 'Заявка на обучение':
            description = request.form.get('training_details')
        elif request_type == 'Заявка на ремонт или обслуживание оборудования':
            description = request.form.get('equipment_issue')
        elif request_type == 'Другое':
            pass  # title и description уже заданы

        new_request = Request(
            user_id=current_user.id,
            title=title or request_type,
            description=description,
            status=request.form.get('status', 'Новая')
        )
        db.session.add(new_request)
        db.session.commit()

        # Логируем создание заявки
        log = Log(
            user_id=current_user.id,
            action="Создал новую заявку",
            details=f"Заявка типа {request_type} была создана с названием {title}. Описание: {description}. Статус: {request.form.get('status', 'Новая')}.",
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        # Если запрос был через AJAX, возвращаем успешный ответ с обновленным списком заявок
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            requests = Request.query.all()
            updated_html = render_template('requests_table.html', requests=requests)
            return jsonify({'success': True, 'updated_requests_html': updated_html})


        flash('Заявка успешно создана.')
        return redirect(url_for('view_requests'))

    return render_template('add_request.html')

# Редактирование заявок
@app.route('/edit_request/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_request(id):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(dictionary=True) as cursor:
            # Проверка прав доступа
            # Администратор может редактировать все заявки
            if current_user.role != 'admin':
                cursor.execute("SELECT * FROM requests WHERE id = %s AND user_id = %s", (id, current_user.id))
            else:
                cursor.execute("SELECT * FROM requests WHERE id = %s", (id,))
                
            request_data = cursor.fetchone()

            # Если заявка не найдена или не принадлежит текущему пользователю (если не админ)
            if request_data is None:
                flash('Заявка не найдена или у вас нет прав для ее редактирования', 'danger')
                return redirect(url_for('view_requests'))  # Перенаправление при отсутствии заявки или прав

            # Если POST-запрос (обновление данных заявки)
            if request.method == 'POST':
                try:
                    new_title = request.form['title']
                    new_description = request.form['description']
                    new_status = request.form['status']

                    # Логирование изменений
                    old_title = request_data['title']
                    old_description = request_data['description']
                    old_status = request_data['status']

                    cursor.execute("""
                        UPDATE requests
                        SET title = %s, description = %s, status = %s
                        WHERE id = %s
                    """, (new_title, new_description, new_status, id))

                    conn.commit()

                    # Логируем изменения
                    log = Log(
                        user_id=current_user.id,
                        action="Изменил заявку",
                        details=f"Изменены данные заявки. Старое название: {old_title}, старое описание: {old_description}, старый статус: {old_status}. Новое название: {new_title}, новое описание: {new_description}, новый статус: {new_status}.",
                        timestamp=datetime.utcnow()
                    )
                    db.session.add(log)
                    db.session.commit()

                    flash('Заявка успешно обновлена', 'success')
                    return redirect(url_for('view_requests'))  # Перенаправление на страницу заявок после успешного обновления

                except Exception as e:
                    flash(f'Произошла ошибка при обновлении заявки: {e}', 'danger')
                    conn.rollback()  # Откат транзакции при ошибке
                    return redirect(url_for('view_requests'))  # Перенаправление после ошибки

    except Exception as e:
        flash(f'Ошибка при работе с базой данных: {e}', 'danger')
        return redirect(url_for('view_requests'))  # Перенаправление при ошибке работы с БД
    finally:
        if conn:
            conn.close()  # Закрытие соединения в блоке finally

    return render_template('edit_request.html', request_data=request_data)

@app.route('/delete_request/<int:request_id>', methods=['POST'])
@login_required
def delete_request(request_id):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # Проверка существования заявки
            cursor.execute("SELECT * FROM requests WHERE id = %s", (request_id,))
            request_data = cursor.fetchone()

            if request_data is None:
                return jsonify({'status': 'error', 'message': 'Заявка не найдена'})

            # Удаление заявки в зависимости от роли пользователя
            if current_user.role == 'admin':
                cursor.execute("DELETE FROM requests WHERE id = %s", (request_id,))
            else:
                # Убедитесь, что проверка пользователя с текущим request_id корректна
                cursor.execute("DELETE FROM requests WHERE id = %s AND user_id = %s", (request_id, current_user.id))

            conn.commit()

            return redirect(url_for('admin'))  # Перенаправление на админ-панель после удаления

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Произошла ошибка при удалении заявки: {e}'})

    finally:
        if conn:
            conn.close()  # Закрытие соединения в блоке finally

@app.route('/activity-log')
@login_required
def activity_log():
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    # Получаем параметры фильтрации
    filter_field = request.args.get('filter_field')
    filter_value = request.args.get('filter_value')
    date_filter_from = request.args.get('date_filter_from')
    date_filter_to = request.args.get('date_filter_to')
    page = request.args.get('page', 1, type=int)  # Пагинация, по умолчанию страница 1

    query = Log.query.join(User)

    # Применяем фильтрацию по пользователю
    if filter_field and filter_value:
        if filter_field == 'user':
            try:
                query = query.filter(Log.user_id == int(filter_value))
            except ValueError:
                pass  # Некорректное значение
        elif filter_field == 'name':
            query = query.filter(User.first_name.ilike(f"%{filter_value}%"))
        elif filter_field == 'surname':
            query = query.filter(User.last_name.ilike(f"%{filter_value}%"))
        elif filter_field == 'patronymic':
            query = query.filter(User.middle_name.ilike(f"%{filter_value}%"))
        elif filter_field == 'phone':
            query = query.filter(User.phone.ilike(f"%{filter_value}%"))
        elif filter_field == 'email':
            query = query.filter(User.email.ilike(f"%{filter_value}%"))

    # Применяем фильтрацию по диапазону дат
    if date_filter_from:
        try:
            start_date = datetime.strptime(date_filter_from, "%Y-%m-%d")
            query = query.filter(Log.timestamp >= start_date)
        except ValueError:
            pass  # Некорректная дата

    if date_filter_to:
        try:
            end_date = datetime.strptime(date_filter_to, "%Y-%m-%d")
            query = query.filter(Log.timestamp <= end_date.replace(hour=23, minute=59, second=59, microsecond=999999))
        except ValueError:
            pass  # Некорректная дата

    # Если не задано поле "по" даты, фильтруем только по одной дате
    elif date_filter_from:
        try:
            single_day = datetime.strptime(date_filter_from, "%Y-%m-%d")
            query = query.filter(Log.timestamp >= single_day)
            query = query.filter(Log.timestamp < (single_day + timedelta(days=1)))
        except ValueError:
            pass  # Некорректная дата

    # Пагинация
    logs = query.order_by(Log.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)
    
    # Загружаем всех пользователей для фильтра
    users = User.query.all()

    return render_template('activity_log.html', logs=logs, users=users)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method != 'POST':
        return render_template('edit_profile.html')

    # Получение данных формы
    first_name = request.form.get('first_name', '').strip()
    last_name = request.form.get('last_name', '').strip()
    middle_name = request.form.get('middle_name', '').strip()
    phone_number = request.form.get('phone_number', '').strip()
    email = request.form.get('email', '').strip()
    new_password = request.form.get('new_password', '').strip()
    image_file = request.files.get('profile_image')

    # Валидация обязательных полей
    if not first_name or not last_name or not email:
        flash('Имя, фамилия и email обязательны.', 'danger')
        return redirect(url_for('edit_profile'))

    # Логирование старых значений
    old_first_name = current_user.first_name
    old_last_name = current_user.last_name
    old_middle_name = current_user.middle_name
    old_phone_number = current_user.phone_number
    old_email = current_user.email
    old_image_url = current_user.image_url

    # Проверка email на уникальность
    if current_user.email != email:
        if User.query.filter_by(email=email).first():
            flash('Этот email уже используется.', 'danger')
            return redirect(url_for('edit_profile'))
        current_user.email = email

    # Обновление текстовых данных
    current_user.first_name = first_name
    current_user.last_name = last_name
    current_user.middle_name = middle_name
    current_user.phone_number = phone_number

    # Обновление пароля, если указан
    if new_password:
        current_user.set_password(new_password)

    # Обработка изображения, если загружено
    if image_file and image_file.filename:
        ext = os.path.splitext(image_file.filename)[1].lower()
        if ext not in ['.jpg', '.jpeg', '.png', '.gif']:
            flash('Неверный формат изображения. Пожалуйста, загрузите JPG, JPEG, PNG или GIF.', 'danger')
            return redirect(url_for('edit_profile'))

        filename = secure_filename(image_file.filename)
        unique_filename = f"{uuid.uuid4().hex}{ext}"

        # Получение папки загрузки
        upload_folder = app.config.get('UPLOAD_FOLDER') or os.path.join(os.getcwd(), 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        upload_path = os.path.join(upload_folder, unique_filename)

        # Сохраняем файл
        image_file.save(upload_path)

        # Удаляем старый файл, если не default.jpg
        if current_user.image_url and current_user.image_url != 'default.jpg':
            old_path = os.path.join(upload_folder, current_user.image_url)
            if os.path.exists(old_path):
                os.remove(old_path)

        current_user.image_url = unique_filename

    db.session.commit()

    # Логирование изменений
    log_details = []
    if old_first_name != current_user.first_name:
        log_details.append(f"Изменено имя с {old_first_name} на {current_user.first_name}")
    if old_last_name != current_user.last_name:
        log_details.append(f"Изменена фамилия с {old_last_name} на {current_user.last_name}")
    if (old_middle_name or '') != (current_user.middle_name or ''):
        log_details.append(f"Изменено отчество с {(old_middle_name or '')} на {(current_user.middle_name or '')}")
    if old_phone_number != current_user.phone_number:
        log_details.append(f"Изменён номер телефона с {old_phone_number} на {current_user.phone_number}")
    if old_email != current_user.email:
        log_details.append(f"Изменён email с {old_email} на {current_user.email}")
    if old_image_url != current_user.image_url:
        log_details.append("Изображение профиля изменено.")

    if log_details:
        log = Log(
            user_id=current_user.id,
            action="Изменил профиль",
            details=", ".join(log_details),
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

    flash('Профиль успешно обновлён.', 'success')
    return redirect(url_for('profile'))

@app.route('/upload_profile_image_ajax', methods=['POST'])
@login_required
def upload_profile_image_ajax():
    image = request.files.get('profile_image')
    if image and image.filename:
        filename = secure_filename(image.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(filepath)
        current_user.image_url = filename
        db.session.commit()
        return jsonify(
            success=True,
            image_url=url_for('static', filename=f'uploads/{filename}'),
        )
    return jsonify(success=False, error='Файл не выбран или ошибка загрузки')

# Редактирование пользователя
@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        # Получаем данные из формы
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        middle_name = request.form['middle_name']
        phone_number = request.form['phone_number']
        role = request.form['role']

        # Получаем старые данные пользователя для записи в лог
        cursor.execute("SELECT * FROM users WHERE id=%s", (id,))
        old_user = cursor.fetchone()

        # Обновляем пользователя в базе данных
        cursor.execute("""
            UPDATE users 
            SET email=%s, first_name=%s, last_name=%s, middle_name=%s, 
                phone_number=%s, role=%s 
            WHERE id=%s
        """, (email, first_name, last_name, middle_name, phone_number, role, id))

        conn.commit()

        # Логируем изменения
        log = Log(
            user_id=current_user.id,
            action="Изменил данные пользователя",
            details=f"Изменены данные пользователя {old_user['first_name']} {old_user['last_name']} (ID: {id}). Старые данные: {old_user}. Новые данные: {first_name} {last_name}, email: {email}, phone: {phone_number}, role: {role}",
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        cursor.close()
        conn.close()

        return redirect(url_for('admin'))

    # Получаем информацию о пользователе для предзаполнения формы
    cursor.execute("SELECT * FROM users WHERE id=%s", (id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template('edit_user.html', user=user)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if request.method == 'POST':
        # Извлечение данных формы
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')

        # Валидация обязательных полей
        if not phone_number or not password:
            flash('Номер телефона и пароль обязательны.', 'error')
            return redirect(url_for('add_user'))

        # Остальные данные (необязательные)
        last_name = request.form.get('last_name') or None
        first_name = request.form.get('first_name') or None
        middle_name = request.form.get('middle_name') or None
        email = request.form.get('email') or None
        role = request.form.get('role') or 'user'

        # Проверка на дубликат телефона
        existing_user = User.query.filter_by(phone_number=phone_number).first()
        if existing_user:
            flash('Пользователь с таким номером телефона уже существует.', 'error')
            return redirect(url_for('add_user'))

        # Хеширование пароля
        hashed_password = generate_password_hash(password)

        # Создание нового пользователя
        new_user = User(
            last_name=last_name,
            first_name=first_name,
            middle_name=middle_name,
            phone_number=phone_number,
            email=email,
            password=hashed_password,
            role=role
        )

        # Добавление в базу данных
        db.session.add(new_user)
        db.session.commit()
        
        # Логируем создание нового пользователя
        log = Log(
            user_id=current_user.id,
            action="Создал нового пользователя",
            details=f"Создан новый пользователь {new_user.first_name} {new_user.last_name}. Email: {new_user.email}, Phone: {new_user.phone_number}, Role: {new_user.role}",
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        flash('Пользователь успешно добавлен.', 'success')

        return redirect(url_for('admin'))

    return render_template('add_user.html')

@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    # Найти пользователя по ID
    user_to_delete = User.query.get(id)
    if user_to_delete:
        # Удалить пользователя
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'Пользователь {user_to_delete.last_name} был удалён.', 'success')
    else:
        flash('Пользователь не найден.', 'error')

    return redirect(url_for('admin'))  # Перенаправление обратно на админ-панель

@app.route('/projects', methods=['GET'])
@login_required
def view_projects():
    status = request.args.get('status')

    if status in ['active', 'completed']:
        projects = Project.query.filter_by(status=status).all()
    else:
        projects = Project.query.filter(Project.status.in_(['active', 'completed'])).all()

    return render_template('view_projects.html', projects=projects, selected_status=status)

# Маршрут для редактирования проекта
@app.route('/edit_project/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_project(id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    project = Project.query.get(id)
    if not project:
        flash('Проект не найден', 'danger')
        return redirect(url_for('view_projects'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        status = request.form['status']  # Получаем новый статус
        image_url = project.image_url  # Сохраняем старое изображение

        # Обработка изображения
        file = request.files.get('image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            image_url = filename

        # Получаем старые данные для лога
        old_title = project.title
        old_description = project.description
        old_image_url = project.image_url
        old_status = project.status  # Старый статус
        old_users = [user.id for user in project.assigned_users]

        # Обновляем поля проекта
        project.title = title
        project.description = description
        project.status = status  # Обновляем статус
        project.image_url = image_url

        # Получаем список выбранных сотрудников (id сотрудников)
        assigned_user_ids = request.form.getlist('users')  # Список id сотрудников

        # Очищаем старую связь между проектом и пользователями
        project.assigned_users.clear()

        # Добавляем новых назначенных сотрудников
        for user_id in assigned_user_ids:
            user = User.query.get(user_id)
            if user:
                project.assigned_users.append(user)

        db.session.commit()

        # Логируем изменения
        new_user_ids = ', '.join(assigned_user_ids)
        old_user_ids = ', '.join(map(str, old_users))
        log = Log(
            user_id=current_user.id,
            action="Изменил проект",
            details=(f"Проект '{old_title}' обновлён. "
                     f"Описание: '{old_description}' → '{description}'. "
                     f"Изображение: '{old_image_url}' → '{image_url}'. "
                     f"Статус: '{old_status}' → '{status}'. "
                     f"Сотрудники: {old_user_ids} → {new_user_ids}."),
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()

        flash('Проект обновлён', 'success')
        return redirect(url_for('admin'))

    # Передаем пользователей и список ID назначенных сотрудников
    users = User.query.all()
    assigned_user_ids = [user.id for user in project.assigned_users]

    return render_template(
        'edit_project.html',
        project=project,
        users=users,
        assigned_user_ids=assigned_user_ids
    )

# Маршрут для добавления нового проекта
@app.route('/add_project', methods=['GET', 'POST'])
@login_required
def add_project():
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        file = request.files.get('image')

        if not file or not allowed_file(file.filename):
            flash('Неверный файл. Пожалуйста, выберите изображение с правильным расширением.', 'danger')
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        assigned_user_ids = request.form.getlist('users')

        new_project = Project(
            title=title,
            description=description,
            image_url=filename,
            user_id=current_user.id
        )

        for user_id in assigned_user_ids:
            user = User.query.get(int(user_id))
            if user:
                new_project.assigned_users.append(user)

        db.session.add(new_project)
        db.session.commit()

        flash('Проект добавлен', 'success')
        return redirect(url_for('admin'))

    # ← ← ← Важно: передаём users в шаблон
    users = User.query.all()
    return render_template('add_project.html', users=users)

@app.route('/delete_project/<int:id>', methods=['POST'])
@login_required  # Например, если только администраторы могут удалять проекты
def delete_project(id):
    project = Project.query.get_or_404(id)
    try:
        db.session.delete(project)
        db.session.commit()
        flash('Проект удален успешно.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Произошла ошибка при удалении проекта.', 'danger')
    return redirect(url_for('admin'))

@app.route('/my_projects', methods=['GET'])
@login_required
def my_projects():
    selected_status = request.args.get('status', '')
    current_sort = request.args.get('sort', 'id')

    # Получаем проекты, в которых состоит текущий пользователь
    query = Project.query.join(Project.assigned_users).filter(User.id == current_user.id)

    # Применяем фильтрацию по статусу
    if selected_status:
        query = query.filter(Project.status == selected_status)

    # Применяем сортировку
    if current_sort == 'title':
        query = query.order_by(Project.title)
    elif current_sort == 'status':
        query = query.order_by(Project.status)
    else:
        query = query.order_by(Project.id)

    projects = query.all()

    return render_template('my_projects.html', projects=projects, selected_status=selected_status, current_sort=current_sort)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)






