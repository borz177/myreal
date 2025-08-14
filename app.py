
from utils import allowed_file
from sqlalchemy import or_
from flask import Flask, jsonify, abort
from sqlalchemy.exc import IntegrityError
from dateutil.relativedelta import relativedelta
from babel.dates import format_datetime
from flask_login import LoginManager, login_user, logout_user, current_user

from flask import Response, render_template, url_for
from flask_migrate import Migrate
from models import User, Item, Payment, License, Investor, Balance, Transaction
from config import Config

from datetime import datetime, date, timezone, timedelta

from werkzeug.utils import secure_filename
from flask import send_file, flash, redirect, request, current_app
from flask_login import login_required
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os
from authlib.integrations.flask_client import OAuth
from flask import session
import secrets
from dotenv import load_dotenv
from flask_migrate import upgrade
from extensions import db


from flask import request, redirect, flash, url_for, abort
import re
from urllib.parse import quote
from flask import send_from_directory
import uuid
from flask_session import Session
from flask_apscheduler import APScheduler
from babel.dates import format_date



load_dotenv(encoding='UTF-8')


config = Config()  # теперь не нужен, так как мы не используем @property

app = Flask(__name__)
app.config.from_object(Config)
# Путь для PDF файлов
app.config['UPLOAD_FOLDER_PDFS'] = os.path.join('static', 'uploads', 'pdfs')
# Путь к монтированной папке (если ты на проде)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

# Важно: убедись, что путь существует, или создай его
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Убедитесь, что папка существует
os.makedirs(app.config['UPLOAD_FOLDER_PDFS'], exist_ok=True)




db.init_app(app)
# Инициализация Flask-Session
Session(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

oauth = OAuth(app)
oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url=app.config["GOOGLE_DISCOVERY_URL"],
    client_kwargs={'scope': 'openid email profile'},
    #redirect_uri=app.config["GOOGLE_REDIRECT_URI"]  # 🔧 теперь это обычная строка
)



scheduler = APScheduler()

def clear_expired_tokens():
    print("Очистка устаревших токенов...")
    expiration_time = datetime.utcnow() - timedelta(days=7)
    expired_items = Item.query.filter(Item.token_created_at != None, Item.token_created_at < expiration_time).all()

    for item in expired_items:
        item.access_token = None
        item.token_created_at = None
        print(f"Токен очищен для item_id={item.id}")

    if expired_items:
        db.session.commit()

# Добавляем задачу в планировщик
scheduler.add_job(
    id='clear_expired_tokens',
    func=clear_expired_tokens,
    trigger='interval',
    hours=12  # раз в 12 часов
)

# Запускаем планировщик при старте Flask
scheduler.init_app(app)
scheduler.start()
# Для локальной разработки (разрешить http)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


# НАСТРОЙКА: политика "до какого дня платить за месяц"
# Варианты:
# 1 — "end_of_month" — до конца месяца (31.07.2025)
# 2 — фиксированный день месяца — например, 15 => до 15 числа месяца (15.07.2025)
# 3 — N дней после даты ожидания — например, 10 дней

PAYMENT_POLICY = {
    "mode": "end_of_month",  # "end_of_month" | "fixed_day" | "grace_days"
    "fixed_day": 15,         # если mode = "fixed_day"
    "grace_days": 10         # если mode = "grace_days"
}


dt = datetime.now()
formatted = format_datetime(dt, locale='ru')
print(formatted)


def get_due_date(expected_date):
    """
    expected_date — дата, когда наступил ожидаемый платёжный месяц
    возвращает крайнюю дату оплаты
    """
    if PAYMENT_POLICY["mode"] == "end_of_month":
        # Конец месяца
        next_month = expected_date + relativedelta(months=1)
        due_date = next_month.replace(day=1) - timedelta(days=1)
        return due_date

    elif PAYMENT_POLICY["mode"] == "fixed_day":
        # Фиксированный день месяца (например, до 15 числа месяца)
        next_month = expected_date + relativedelta(months=1)
        due_day = PAYMENT_POLICY["fixed_day"]
        try:
            due_date = next_month.replace(day=due_day)
        except ValueError:
            # Если в месяце нет такого дня (например, 30 февраля), берём последний день месяца
            next_month = next_month + relativedelta(months=1)
            due_date = next_month.replace(day=1) - timedelta(days=1)
        return due_date

    elif PAYMENT_POLICY["mode"] == "grace_days":
        # N дней после ожидаемой даты
        grace_days = PAYMENT_POLICY["grace_days"]
        due_date = expected_date + timedelta(days=grace_days)
        return due_date

    else:
        # По умолчанию — конец месяца
        next_month = expected_date + relativedelta(months=1)
        due_date = next_month.replace(day=1) - timedelta(days=1)
        return due_date



# Для локальной разработки (разрешить http)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))






# Главная страница
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))  # Если пользователь залогинен, редиректим на dashboard
    return render_template("home.html")  # Если не залогинен, показываем страницу входа



@app.route("/login")
def login():
    # Генерируем уникальные state и nonce для каждой сессии
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    print("BEFORE REDIRECT — SESSION:", session)

    # Сохраняем в сессии с временной меткой (используем timezone-aware datetime)
    session['oauth_state'] = {
        'value': state,
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    session['nonce'] = nonce

    session['next_url'] = request.args.get('next')  # Сохраняем next URL из запроса

    # Формируем redirect_uri с явным указанием протокола
    #redirect_uri = url_for('auth_callback', _external=True)
    redirect_uri = Config.GOOGLE_REDIRECT_URI
    return oauth.google.authorize_redirect(
        redirect_uri=redirect_uri,
        state=state,
        nonce=nonce,
        prompt="select_account",
        include_granted_scopes="true",
        access_type="offline"
    )

@app.route("/auth/callback")
def auth_callback():
    if 'state' not in request.args:
        return "Missing state parameter", 400

    saved_state = session.pop('oauth_state', None)
    if not saved_state:
        return "Session expired or invalid state", 400

    state_created = datetime.fromisoformat(saved_state['created_at'])
    if datetime.now(timezone.utc) - state_created > timedelta(minutes=10):
        return "State expired", 400

    if request.args['state'] != saved_state['value']:
        return "Invalid state parameter", 400

    nonce = session.pop('nonce', None)
    if not nonce:
        return "Nonce missing", 400

    try:
        token = oauth.google.authorize_access_token()
        user_info = oauth.google.parse_id_token(token, nonce=nonce)
        if not user_info or 'email' not in user_info:
            return "Failed to retrieve user info", 400

        email = user_info.get("email", "").lower()
        user = User.query.filter_by(email=email).first()

        if not user:
            if email == "borz017795@gmail.com":
                app.logger.info("Creating admin user...")

                user = User(email=email, is_admin=True)
                db.session.add(user)
                db.session.flush()  # получаем user.id

                # Выдаём лицензию на 1 год
                license = License(
                    user_id=user.id,
                    activated_at=datetime.utcnow(),
                    expires_at=datetime.utcnow() + timedelta(days=365),
                    is_active=True,
                    activated_by=None
                )
                db.session.add(license)
                db.session.commit()
            else:
                return render_template("license_required.html")
        # Пользователь найден → логиним
        login_user(user, remember=True)

        # Редиректим
        return redirect(session.pop("next_url", None) or url_for("dashboard"))

    except Exception as e:
        app.logger.error(f"OAuth error: {str(e)}", exc_info=True)
        return "Authentication failed", 400





# 🔒 Страница "Лицензия требуется"
@app.route("/license-required")
def license_required_page():
    return render_template("license_required.html")







# 🔓 Выход
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route("/admin/users")
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)

    search_query = request.args.get("search")  # Получаем поисковый запрос
    if search_query:
        # Фильтруем пользователей по email (регистронезависимый поиск)
        users = User.query.filter(User.email.ilike(f"%{search_query}%")).all()
    else:
        users = User.query.all()  # Если поиск пустой — выводим всех

    return render_template("admin_users.html", users=users)

@app.route("/admin/add_user", methods=["POST"])
@login_required
def add_user_by_email():
    if not current_user.is_admin:
        abort(403)

    email = request.form.get("email", "").strip().lower()
    if not email:
        return redirect(url_for("admin_users"))

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, is_admin=False)
        db.session.add(user)
        db.session.flush()  # user.id

    # Выдать лицензию на 1 год
    license = License(
        user_id=user.id,
        activated_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=365),
        is_active=True,
        activated_by=current_user.id
    )
    db.session.add(license)
    db.session.commit()

    flash("Пользователь добавлен и лицензия выдана", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/toggle_admin/<int:user_id>", methods=["POST"])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    return redirect(url_for("admin_users"))
@app.route("/admin/activate_license/<int:user_id>", methods=["POST"])
@login_required
def activate_license(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    expiration_str = request.form.get("expiration", "").strip()

    if not expiration_str:
        flash("Дата окончания обязательна", "danger")
        return redirect(url_for("admin_users"))

    try:
        expiration_date = datetime.strptime(expiration_str, "%d.%m.%Y")
    except ValueError:
        flash("Неверный формат даты. Используйте дд.мм.гггг", "danger")
        return redirect(url_for("admin_users"))

    # Деактивируем все предыдущие лицензии пользователя
    for license in user.licenses:
        license.is_active = False

    # Создаём новую лицензию
    new_license = License(
        user_id=user.id,
        activated_at=datetime.utcnow(),
        expires_at=expiration_date,
        is_active=True,
        activated_by=current_user.id
    )
    db.session.add(new_license)
    db.session.commit()

    flash(f"Новая лицензия активирована до {expiration_date.strftime('%d.%m.%Y')}", "success")
    return redirect(url_for("admin_users"))

#Страница истории лицензий пользователя
@app.route("/admin/user/<int:user_id>/licenses")
@login_required
def user_license_history(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    licenses = License.query.filter_by(user_id=user.id).order_by(License.activated_at.desc()).all()
    return render_template("license_history.html", user=user, licenses=licenses)




#Роут для деактивации лицензии вручную
@app.route("/admin/deactivate_license/<int:license_id>", methods=["POST"])
@login_required
def deactivate_license(license_id):
    if not current_user.is_admin:
        abort(403)

    license = License.query.get_or_404(license_id)
    license.is_active = False
    db.session.commit()

    flash("Лицензия деактивирована", "warning")
    return redirect(url_for("user_license_history", user_id=license.user_id))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.email == current_user.email:
        # Защита от удаления себя
        return redirect(url_for("admin_users"))

    if user.items or user.licenses:  # 👈 проверяем связи
        flash("Невозможно удалить пользователя — есть связанные данные.", "danger")
        return redirect(url_for("admin_users"))

    db.session.delete(user)
    db.session.commit()
    flash("Пользователь удалён", "success")
    return redirect(url_for("admin_users"))








@app.route("/offline")
def offline():
    return render_template("offline.html")

#форматирование суммы руб
def format_rubles(value):
    try:
        value = float(value)
        formatted = "{:,.2f}".format(value).replace(",", " ").replace(".", ",")
        return f"{formatted} ₽"
    except (ValueError, TypeError):
        return value

# Регистрируем фильтр в Jinja
app.jinja_env.filters['rub'] = format_rubles


@app.route('/item/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    investors = Investor.query.filter_by(user_id=current_user.id).all()
    if not (current_user.is_admin or item.user_id == current_user.id):
        abort(403)



    if request.method == 'POST':
        item.name = request.form['name']
        item.price = request.form['price']
        item.purchase_price = request.form['purchase_price']
        item.installments = request.form['installments']
        item.client_name = request.form['client_name']
        item.client_phone = request.form['client_phone']
        item.guarantor_name = request.form['guarantor_name']
        item.guarantor_phone = request.form['guarantor_phone']
        item.user_id = current_user.id
        item.investor_id = request.form.get('investor_id') or None
        item.client_address = request.form.get('client_address', '').strip()

        # Обработка даты первого платежа
        first_payment_date_str = request.form.get('first_payment_date')
        if first_payment_date_str:
            try:
                item.first_payment_date = datetime.strptime(first_payment_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash("Неверный формат даты первого платежа", "warning")
        else:
            item.first_payment_date = None
        # Удаление фото
        if 'delete_photo' in request.form and item.photo_url:
            photo_path = os.path.join(current_app.root_path, 'static', 'uploads', item.photo_url)
            if os.path.exists(photo_path):
                os.remove(photo_path)
            item.photo_url = None

        # Загрузка нового фото
        photo = request.files.get('photo')
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))

            item.photo_url = filename

        db.session.commit()
        flash('Товар обновлён успешно.', 'success')
        return redirect(url_for('contracts'))

    return render_template('edit_item.html', item=item, investors=investors)


@app.route('/item/delete/<int:item_id>', methods=['POST'])
@login_required

def delete_item(item_id):
    item = Item.query.get_or_404(item_id)

    if not (current_user.is_admin or item.user_id == current_user.id):
        flash("Доступ запрещён", "danger")
        return redirect(url_for('contracts'))
    if item.payments:
        flash("⚠️ Удаление невозможно — по договору уже были внесены платежи.", "danger")
        return redirect(url_for('contracts'))

    try:
        db.session.delete(item)
        db.session.commit()
        flash("✅ Договор успешно удалён.", "info")
    except IntegrityError:
        db.session.rollback()
        flash("❌ Ошибка при удалении: договор связан с другими данными.", "danger")

    return redirect(url_for('contracts'))





# Личный кабинет / добавление товара
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():

    if request.method == "POST":

        if not current_user.active_license:
            flash("У вас нет активной лицензии. Оформление невозможно.", "danger")
            return redirect(url_for("dashboard"))

        name = request.form.get("name")
        price = float(request.form.get("price"))
        purchase_price = float(request.form["purchase_price"])
        installments = int(request.form.get("installments"))
        client_name = request.form.get("client_name")
        guarantor_name = request.form.get("guarantor_name")
        client_phone = request.form["client_phone"]
        guarantor_phone = request.form["guarantor_phone"]
        photo = request.files.get("photo")
        photo_url = None
        down_payment_str = request.form.get("down_payment", "0")  # По умолчанию "0"
        down_payment = float(down_payment_str) if down_payment_str else 0.0
        investor_id_raw = request.form.get("investor_id")
        print(f"DEBUG: investor_id from form = '{investor_id_raw}'")
        client_address = request.form.get("client_address", "").strip()

        # 🔹 Обработка даты первого платежа
        first_payment_date_str = request.form.get("first_payment_date")
        first_payment_date = None
        if first_payment_date_str:
            try:
                first_payment_date = datetime.strptime(first_payment_date_str, "%Y-%m-%d").date()
            except ValueError:
                flash("Неверный формат даты первого платежа. Используйте формат ГГГГ-ММ-ДД.", "danger")
                return redirect(url_for("dashboard"))



        # Безопасная обработка
        investor_id = None
        if investor_id_raw and investor_id_raw != 'None':
            try:
                investor_id = int(investor_id_raw)
            except ValueError:
                investor_id = None

        # 🔹 Найти счёт вне зависимости от того, откуда investor_id
        # 🔹 Найдём счёт инвестора
        selected_balance = Balance.query.filter_by(
            user_id=current_user.id,
            investor_id=investor_id
        ).order_by(Balance.is_default.desc()).first()

        if not selected_balance:
            flash("Не найден счёт, привязанный к выбранному инвестору.", "danger")
            return redirect(url_for("dashboard", investor_id=investor_id or ""))

        # 🔹 Проверка: хватает ли средств у инвестора для покупки
        if selected_balance.amount < purchase_price:
            flash("Недостаточно средств на счёте инвестора для оформления товара.", "danger")
            return redirect(url_for("dashboard", investor_id=investor_id or ""))

        # 🔹 Вычитаем закупочную цену
        selected_balance.amount -= purchase_price

        # 🔹 Добавляем первый взнос клиента (если есть)
        if down_payment > 0:
            selected_balance.amount += down_payment

        db.session.add(selected_balance)

        created_at_str = request.form.get("created_at")
        created_at = datetime.strptime(created_at_str, "%Y-%m-%d") if created_at_str else datetime.utcnow()

        if photo and allowed_file(photo.filename):
            filename = f"{uuid.uuid4().hex}_{secure_filename(photo.filename)}"
            upload_path = current_app.config["UPLOAD_FOLDER"]
            os.makedirs(upload_path, exist_ok=True)
            photo.save(os.path.join(upload_path, filename))
            photo_url = filename

        last_number = db.session.query(
            db.func.max(Item.user_contract_number)
        ).filter_by(user_id=current_user.id).scalar()

        item = Item(
            name=name,
            price=price,
            purchase_price=purchase_price,
            buyer=current_user.email,
            user_id=current_user.id,
            status="Оформлен",
            installments=installments,
            client_name=client_name,
            client_phone=client_phone,
            guarantor_name=guarantor_name,
            guarantor_phone=guarantor_phone,
            photo_url=photo_url,
            down_payment=down_payment,
            created_at=created_at,
            first_payment_date=first_payment_date,
            client_address=client_address,
            user_contract_number=(last_number or 0) + 1,
            investor_id=investor_id  # уже int или None — ОК!
        )
        db.session.add(item)
        db.session.commit()
        flash("Товар успешно оформлен!", "success")
        # 👇 Редирект на dashboard c выбранным инвестором, чтобы он остался выбран
        return redirect(url_for("dashboard", investor_id=investor_id if investor_id else ""))

    # GET-запрос — тут правильно
    selected_id = request.args.get("investor_id", type=int)

    today = date.today()
    items = Item.query.filter(
        Item.user_id == current_user.id,
        db.func.date(Item.created_at) == today
    ).all()

    license_expiration = current_user.active_license.expires_at if current_user.active_license else None

    if current_user.is_admin:
        investors = Investor.query.all()
    else:
        investors = Investor.query.filter_by(user_id=current_user.id).all()

    return render_template(
        "dashboard.html",
        items=items,
        current_date=date.today().strftime("%Y-%m-%d"),
        license_expiration=license_expiration,
        investors=investors,
        selected_id=selected_id,
        user=current_user
    )



@app.route("/autocomplete")
@login_required
def autocomplete():
    query = request.args.get("query", "").strip().lower()

    # Поиск по client_name с учетом user_id
    results = (
        db.session.query(Item.client_name)
        .filter(
            Item.user_id == current_user.id,
            Item.client_name.ilike(f"%{query}%")
        )
        .distinct()
        .limit(10)
        .all()
    )

    # Преобразуем к списку строк
    client_names = [name for (name,) in results]

    return jsonify(client_names)



@app.route("/investors/add", methods=["GET", "POST"])
@login_required
def add_investor():
    if request.method == "POST":
        name = request.form["name"]
        initial_balance = float(request.form.get("initial_balance", 0.0))  # Получаем сумму из формы
        # Ограничиваем допустимый диапазон
        profit_percent = int(request.form.get("profit_percent", 50))

        if not (0 <= profit_percent <= 100):
            flash("Процент прибыли должен быть от 0 до 100", "danger")
            return redirect(url_for("add_investor"))

        # Создание инвестора
        investor = Investor(name=name, user_id=current_user.id, profit_percent=profit_percent)
        db.session.add(investor)
        db.session.flush()  # Получаем ID инвестора без коммита всей транзакции

        # Создание счета с указанной суммой
        balance = Balance(
            user_id=current_user.id,
            investor_id=investor.id,
            amount=initial_balance,
            name="Наличные:",  # Примерное имя счёта
            is_default=False  # Не делаем счёт по умолчанию для инвестора
        )
        db.session.add(balance)
        db.session.commit()

        flash("Инвестор и счёт успешно добавлены!", "success")
        return redirect(url_for("dashboard"))

    investors = Investor.query.filter_by(user_id=current_user.id).all()
    return render_template("add_investor.html", investors=investors)


@app.route('/investors/update_percent/<int:investor_id>', methods=['POST'])
def update_profit_percent(investor_id):
    investor = Investor.query.get_or_404(investor_id)
    try:
        profit_percent = int(request.form['profit_percent'])

        if not (0 <= profit_percent <= 100):
            flash("Процент прибыли должен быть от 0 до 100", "danger")
            return redirect(url_for("add_investor"))

        investor.profit_percent = profit_percent
        db.session.commit()
    except:
        flash('Ошибка при обновлении процента прибыли', "danger")
    return redirect(url_for('add_investor'))


@app.route("/investors/delete/<int:investor_id>", methods=["POST"])
@login_required
def delete_investor(investor_id):
    investor = Investor.query.get_or_404(investor_id)

    if investor.user_id != current_user.id:
        abort(403)

    # Проверка: есть ли связанные товары
    if investor.items:
        flash("Нельзя удалить инвестора — есть связанные товары.", "danger")
        return redirect(url_for("add_investor"))

    db.session.delete(investor)
    db.session.commit()
    flash("Инвестор удалён.", "info")
    return redirect(url_for("add_investor"))



#кликабельная строка внутри

@app.route("/payments")
@login_required
def payments():
    try:
        selected_id = request.args.get("investor_id", type=int)
        investors = Investor.query.filter_by(user_id=current_user.id).all()

        item_query = Item.query.filter_by(user_id=current_user.id)
        payment_query = Payment.query.join(Item).filter(
            Payment.user_id == current_user.id,
            Item.user_id == current_user.id
        )

        # 🔽 Фильтрация по инвестору
        if selected_id is not None:
            item_query = item_query.filter(Item.investor_id == selected_id)
            payment_query = payment_query.filter(Item.investor_id == selected_id)
            balances = Balance.query.filter_by(user_id=current_user.id, investor_id=selected_id).all()
        else:
            balances = Balance.query.filter_by(user_id=current_user.id).all()

        items = item_query.all()
        payments = payment_query.all()

        total_invested = sum(item.purchase_price or 0 for item in items)
        total_paid = sum(payment.amount for payment in payments)

        active_items = [item for item in items if item.status == "Оформлен"]
        monthly_profit = sum(
            ((item.price or 0) - (item.purchase_price or 0)) / item.installments
            for item in active_items
            if item.installments and item.price and item.purchase_price
        )
        total_profit = sum(
            (item.price or 0) - (item.purchase_price or 0)
            for item in items
            if item.price and item.purchase_price
        )

        # 🔽 Прибыль инвесторов
        investor_profit = {}
        for investor in investors:
            investor_profit[investor.id] = total_profit * (investor.profit_percent / 100)

        # 🔽 Ваша прибыль (общая прибыль минус прибыль инвесторов)
        my_profit = total_profit - sum(investor_profit.values())

        return render_template(
            "payments.html",
            total_invested=round(total_invested, 2),
            total_paid=round(total_paid, 2),
            monthly_profit=round(monthly_profit, 2),
            total_profit=round(total_profit, 2),
            my_profit=round(my_profit, 2),
            investor_profit=investor_profit,
            items=items,
            payments=payments,
            investors=investors,
            selected_id=selected_id,
            balances=balances  # 👈 передаём отфильтрованные счета
        )

    except Exception as e:
        app.logger.error(f"Error in payments route: {str(e)}")
        return f"Ошибка при загрузке данных: {str(e)}", 500

@app.route("/add_payment", methods=["GET", "POST"])
@login_required
def add_payment():
    selected_client = request.args.get("client_name") or request.form.get("client_name")
    payments = []
    error = None

    all_clients = sorted(
        [
            c[0]
            for c in db.session.query(Item.client_name)
            .filter(Item.user_id == current_user.id)
            .distinct()
            .all()
            if c[0]
        ],
        key=lambda x: str(x).lower()
    )

    # ✅ Инициализируем ДО if
    items = []
    items_data = []  # ← теперь всегда существует

    if selected_client:
        try:
            exact_client_name = next(
                (
                    name for name in db.session.query(Item.client_name)
                    .filter(Item.user_id == current_user.id)
                    .distinct()
                    .all()
                    if name[0] and name[0].lower() == selected_client.lower()
                ),
                (selected_client,)
            )[0]

            items = Item.query.filter(
                db.func.lower(Item.client_name) == db.func.lower(exact_client_name),
                Item.user_id == current_user.id,
                Item.status == "Оформлен"
            ).all()

            # ✅ Преобразуем в словари
            items_data = [
                {
                    "id": item.id,
                    "name": item.name,
                    "price": float(item.price) if item.price else 0.0,
                    "purchase_price": float(item.purchase_price) if item.purchase_price else 0.0,
                }
                for item in items
            ]

            payments = db.session.query(Payment) \
                .join(Item) \
                .filter(
                    db.func.lower(Item.client_name) == db.func.lower(exact_client_name),
                    Item.user_id == current_user.id
                ) \
                .order_by(Payment.id.desc()) \
                .all()

        except Exception as e:
            error = f"Ошибка при загрузке данных: {str(e)}"
            items_data = []  # ← на случай ошибки
            payments = []

    # ... (POST-логика остаётся без изменений)




    if request.method == "POST":
        if not current_user.active_license:
            flash("У вас нет активной лицензии!", "danger")
            return redirect(url_for("add_payment"))

        try:
            item_id = int(request.form.get("item_id"))
            amount = float(request.form.get("amount"))
            created_at_str = request.form.get("created_at")
            created_at = datetime.strptime(created_at_str, "%Y-%m-%d") if created_at_str else datetime.utcnow()

            item = Item.query.filter_by(id=item_id, user_id=current_user.id).first()
            if not item:
                raise Exception("Товар не найден или не принадлежит текущему пользователю")

            # Найдём нужный счёт (Balance), связанный с инвестором (если есть)
            # Найдём нужный счёт (Balance), связанный с инвестором (если есть)
            if item.investor_id:
                balance = Balance.query.filter_by(
                    user_id=current_user.id,
                    investor_id=item.investor_id
                ).order_by(Balance.is_default.desc(), Balance.created_at.desc()).first()
            else:
                balance = Balance.query.filter_by(
                    user_id=current_user.id,
                    investor_id=None
                ).order_by(Balance.is_default.desc(), Balance.created_at.desc()).first()

            if not balance:
                raise Exception("Не найден счёт для списания средств")

            # Добавляем сумму на счёт, а затем проверяем, хватает ли средств
            balance.amount += amount

            if balance.amount < amount:
                raise Exception("Недостаточно средств на счёте")

            # Добавляем платёж
            payment = Payment(
                item_id=item_id,
                user_id=current_user.id,
                amount=amount,
                created_at=created_at
            )
            db.session.add(payment)

            # Обновим статус товара, если всё выплачено
            total_paid = sum(p.amount for p in item.payments) + amount
            if item.price and total_paid >= item.price:
                item.status = "Завершен"

            db.session.commit()

            flash("Платёж успешно добавлен", "success")
            return redirect(url_for("add_payment", client_name=selected_client))

        except Exception as e:
            db.session.rollback()
            error = f"Ошибка при сохранении платежа: {str(e)}"

    return render_template(
        "add_payment.html",
        items=items_data,  # ✅ Теперь всегда определён
        all_clients=all_clients or [],
        payments=payments or [],
        client_name=selected_client,
        current_date=datetime.today().strftime("%Y-%m-%d"),
        error=error,
    )

@app.route("/search_clients")
@login_required
def search_clients():
    term = request.args.get("term", "")
    clients = (
        db.session.query(Item.client_name)
        .filter(Item.client_name.ilike(f"%{term}%"))
        .filter(Item.user_id == current_user.id)
        .distinct()
        .limit(10)
        .all()
    )
    results = [{"label": name[0], "value": name[0]} for name in clients]
    return jsonify(results)



@app.route("/payments/<int:item_id>", methods=["POST"])
@login_required
def make_payment(item_id):
    item = Item.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()

    if not item.price or not item.months or item.months == 0:
        flash("У товара не указана цена или срок рассрочки", "danger")
        return redirect(url_for("payments"))

    monthly_payment = round(item.price / item.months, 2)

    # Пересчитываем сумму оплаты
    total_paid = sum(p.amount for p in item.payments if not p.is_deleted)
    if total_paid >= item.price:
        flash("Этот товар уже полностью оплачен", "info")
        return redirect(url_for("payments"))

    # Выбор счёта
    if item.investor_id:
        balance = Balance.query.filter_by(
            user_id=current_user.id,
            investor_id=item.investor_id
        ).order_by(Balance.is_default.desc(), Balance.created_at.desc()).first()
    else:
        balance = Balance.query.filter_by(
            user_id=current_user.id,
            investor_id=None
        ).order_by(Balance.is_default.desc(), Balance.created_at.desc()).first()

    if not balance:
        flash("Не найден подходящий счёт для инвестора", "danger")
        return redirect(url_for("payments"))

    try:
        # Увеличиваем баланс
        balance.amount += monthly_payment

        # Пересчитываем сумму после платежа
        total_paid_after = total_paid + monthly_payment

        # Обновляем статус по сумме
        item.status = "Завершен" if item.is_paid else "Оформлен"

        # Создаём платеж
        payment = Payment(
            item_id=item.id,
            amount=monthly_payment,
            user_id=current_user.id,
            balance_id=balance.id,
            balance_snapshot=balance.amount - monthly_payment,
            description=f"Ежемесячный платёж от {item.client_name}",
            is_deleted=False,
            created_at=datetime.utcnow(),
            date=datetime.utcnow()
        )
        db.session.add(payment)
        db.session.commit()

        flash("Платёж успешно проведён", "success")

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Ошибка при проведении платежа: {e}")
        flash("Произошла ошибка", "danger")

    return redirect(url_for("payments"))

@app.route("/api/items_by_client/<client_name>")
@login_required
def items_by_client(client_name):
    items = Item.query.filter_by(client_name=client_name, user_id=current_user.id).all()
    items_data = [
        {"id": item.id, "name": item.name, "price": item.price, "status": item.status}
        for item in items
    ]
    return jsonify(items_data)


@app.route("/delete_payment/<int:payment_id>", methods=["POST"])
@login_required
def delete_payment(payment_id):
    payment = Payment.query.get_or_404(payment_id)
    item = payment.item

    # проверяем права
    if item.user_id != current_user.id and not current_user.is_admin:

       abort(403)

    # удаляем платёж
    db.session.delete(payment)

    # пересчитываем статус и количество
    db.session.flush()  # чтобы item.payments «увидел» удаление в этой же сессии
    item.payments_made = len(item.payments)
    if sum(p.amount for p in item.payments) < item.price:
        item.status = "Оформлен"

    db.session.commit()
    flash("Платёж удалён", "danger")

    client_name = request.form.get("client_name") or item.client_name
    return redirect(url_for("add_payment", client_name=client_name))

# Клиенты


@app.route("/clients", methods=["GET", "POST"])
@login_required
def clients():


    search_query = request.form.get("search", "").strip()

    query = db.session.query(Item.client_name).filter(Item.user_id == current_user.id)

    if search_query:
        query = query.filter(Item.client_name.ilike(f"%{search_query}%"))

    client_names = query.distinct().all()

    all_clients_data = []

    for (client_name,) in client_names:
        items = Item.query.filter_by(client_name=client_name, user_id=current_user.id).all()
        client_data = []
        total_debt = 0

        for item in items:
            total_paid = sum(payment.amount for payment in item.payments)
            installment_price = item.price or 0
            down_payment = item.down_payment or 0
            remaining = installment_price - down_payment - total_paid
            if remaining < 0:
                remaining = 0
            total_debt += remaining

            client_data.append({
                "item": item,
                "payments": item.payments,
                "total_paid": total_paid + down_payment,
                "remaining": remaining
            })

        all_clients_data.append({
            "client_name": client_name,
            "client_data": client_data,
            "total_debt": total_debt
        })

    return render_template(
        "clients.html",
        all_clients_data=all_clients_data,
        search_query=search_query
    )


@app.route("/clients/<client_name>")
@login_required
def client_detail(client_name):
    # Убедимся, что такие товары есть у текущего пользователя
    items = Item.query.filter_by(client_name=client_name, user_id=current_user.id).all()

    if not items:
        abort(403)

    client_data = []
    total_debt = 0

    for item in items:
        total_paid = sum(payment.amount for payment in item.payments)
        installment_price = item.price or 0
        down_payment = item.down_payment or 0
        remaining = installment_price - down_payment - total_paid
        if remaining < 0:
            remaining = 0
        total_debt += remaining

        client_data.append({
            "item": item,
            "payments": item.payments,
            "total_paid": total_paid + down_payment,
            "remaining": remaining
        })

    return render_template(
        "client_detail.html",
        client_name=client_name,
        client_data=client_data,
        total_debt=total_debt
    )




@app.route("/items/<int:item_id>/payments", methods=["GET", "POST"])
@login_required
def item_payments(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    if request.method == "POST":
        if "add_payment" in request.form:
            try:
                amount = float(request.form.get("amount"))
                created_at_str = request.form.get("created_at")
                created_at = datetime.strptime(created_at_str, "%Y-%m-%d") if created_at_str else datetime.utcnow()

                # НАХОДИМ СЧЁТ
                balance = Balance.query.filter_by(user_id=current_user.id, is_default=True).first()
                if not balance:
                    flash("Нет счёта по умолчанию.", "danger")
                    return redirect(url_for("item_payments", item_id=item_id))

                # ✅ ДОБАВЛЯЕМ ДЕНЬГИ НА СЧЁТ (платёж получен)
                balance.amount += amount

                # СОЗДАЁМ ПЛАТЕЖ
                payment = Payment(
                    item_id=item.id,
                    amount=amount,
                    user_id=current_user.id,
                    date=created_at,
                    created_at=created_at
                )
                db.session.add(payment)
                db.session.commit()

                # Пересчитываем статус
                item.status = "Завершен" if item.is_paid else "Оформлен"

                db.session.commit()

                flash("Платёж успешно добавлен", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"Ошибка при добавлении платежа: {str(e)}", "danger")


        elif "delete_payment_id" in request.form:

            try:

                payment_id = int(request.form.get("delete_payment_id"))

                payment = Payment.query.get_or_404(payment_id)

                if payment.item.user_id != current_user.id and not current_user.is_admin:
                    abort(403)

                if payment.is_deleted:

                    flash("Платёж уже удалён.", "info")

                else:

                    # 🔎 Пытаемся получить счёт

                    balance = payment.balance_rel  # через relationship

                    if not balance:

                        # ❌ Связь сломана: balance_id есть, но объект не загрузился

                        flash("Ошибка: не удаётся найти счёт для платежа. Данные повреждены.", "danger")

                        app.logger.error(
                            f"Payment {payment.id} has balance_id={payment.balance_id}, but balance_rel is None")

                    elif balance.user_id != current_user.id:

                        # ❌ Доступ к чужому счёту

                        flash("Ошибка: счёт не принадлежит вам.", "danger")

                    else:

                        # ✅ Всё ок — списываем

                        balance.amount -= payment.amount

                        payment.is_deleted = True

                        # Обновляем статус товара

                        item = payment.item

                        total_paid = sum(p.amount for p in item.payments if not p.is_deleted)

                        item.status = "Завершен" if total_paid >= item.price else "Оформлен"

                        db.session.commit()

                        flash("Платёж удалён — сумма списана с счёта", "warning")

                        return redirect(url_for("item_payments", item_id=item.id))


            except Exception as e:

                db.session.rollback()

                app.logger.error(f"Ошибка при удалении платежа: {e}")

                flash("Ошибка при удалении платежа", "danger")

            return redirect(url_for("item_payments", item_id=item_id))


    # Загружаем все платежи
    payments = Payment.query.filter_by(item_id=item.id).order_by(Payment.created_at.desc()).all()

    total_paid = sum(p.amount for p in payments if not p.is_deleted)
    down_payment = item.down_payment or 0
    installment_price = item.price or 0
    remaining = max(installment_price - total_paid - down_payment, 0)
    current_date = datetime.today().strftime("%Y-%m-%d")

    # Генерируем токен, если его нет
    if not item.access_token:
        item.generate_access_token()
        db.session.commit()

    return render_template(
        "item_payments.html",
        item=item,
        payments=payments,
        total_paid=total_paid,
        remaining=remaining,
        current_date=current_date
    )






#pdf экспорт

@app.route("/pdf/<string:token>")
def export_pdf_by_token(token):
    item = Item.query.filter_by(access_token=token).first_or_404()

    # Проверка срока действия токена
    if not item.token_created_at or item.token_created_at < datetime.utcnow() - timedelta(days=7):
        abort(403, description="Срок действия ссылки истёк.")

    # ✅ Фильтруем: только активные платежи
    payments = Payment.query.filter_by(
        item_id=item.id,
        is_deleted=False  # ✅ Только неудалённые
    ).order_by(Payment.created_at.asc()).all()

    # PDF генерация
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=60,
        rightMargin=40,
        topMargin=40,
        bottomMargin=30
    )

    font_path = os.path.join('static', 'fonts', 'DejaVuSans.ttf')
    pdfmetrics.registerFont(TTFont('DejaVuSans', font_path))
    styles = getSampleStyleSheet()
    styleH = ParagraphStyle('Heading', parent=styles['Heading2'], fontName='DejaVuSans', fontSize=16, leading=20, alignment=1)
    styleN = ParagraphStyle('Normal', parent=styles['Normal'], fontName='DejaVuSans', fontSize=12, leading=15)

    elements = []

    # ✅ Пересчитываем оплачено: только активные платежи
    total_paid = item.down_payment + sum(p.amount for p in payments)
    remaining = item.price - total_paid

    elements.extend([
        Paragraph("Акт сверки", styleH),
        Spacer(1, 12),
        Paragraph(f"Клиент: {item.client_name}", styleN),
        Spacer(1, 10),
        Paragraph(f"Товар: {item.name}", styleN),
        Spacer(1, 10),
        Paragraph(f"Дата оформления: {item.created_at.strftime('%d.%m.%Y')}", styleN),
        Spacer(1, 10),
        Paragraph(f"Сумма: {format_rubles(item.price)}", styleN),
        Spacer(1, 10),
        Paragraph(f"Первый взнос: {format_rubles(item.down_payment)}", styleN),
        Spacer(1, 10),
        Paragraph(f"Оплачено: {format_rubles(total_paid)}", styleN),
        Spacer(1, 10),
        Paragraph(f"Остаток: {format_rubles(remaining)}", styleN),
        Spacer(1, 10),
        Paragraph(f"Срок рассрочки: {item.installments} мес.", styleN),
        Spacer(1, 10),
        Paragraph(f"Ежемесячный платёж: {round((item.price - item.down_payment) / item.installments)} ₽", styleN),
        Spacer(1, 12),
    ])

    # Таблица платежей
    data = [['№', 'Дата', 'Сумма', 'Остаток']]
    current_remaining = item.price  # Начинаем с полной цены
    row_index = 1
    first_payment_row = None

    # Учёт первого взноса
    if item.down_payment:
        current_remaining -= item.down_payment
        data.append([
            str(row_index),
            f"{item.created_at.strftime('%d.%m.%Y')} (Взнос)",
            format_rubles(item.down_payment),
            format_rubles(current_remaining)
        ])
        first_payment_row = row_index
        row_index += 1

    # Остальные платежи (только активные)
    for p in payments:
        current_remaining -= p.amount
        data.append([
            str(row_index),
            p.created_at.strftime('%d.%m.%Y'),
            format_rubles(p.amount),
            format_rubles(current_remaining)
        ])
        row_index += 1

    # Создание таблицы
    table = Table(data, colWidths=[30, 140, 100, 100], hAlign='LEFT')

    # Стилизация
    table_style = [
        ('FONTNAME', (0, 0), (-1, -1), 'DejaVuSans'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a90e2')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
    ]

    # Подсветка первого взноса
    if first_payment_row:
        table_style.append(
            ('BACKGROUND', (0, first_payment_row), (-1, first_payment_row), colors.HexColor('#d0f0c0'))
        )

    table.setStyle(TableStyle(table_style))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{item.client_name}_акт_сверки.pdf",
        mimetype='application/pdf'
    )

@app.route('/whatsapp_link/<int:item_id>')
def whatsapp_link(item_id):
    item = Item.query.get_or_404(item_id)

    if item.user_id != current_user.id and not current_user.is_admin:
        abort(403)

    if not item.client_phone:
        flash("У клиента не указан номер телефона.", "danger")
        return redirect(url_for('clients'))

    # Проверка токена и генерация при необходимости
    if not item.access_token or not item.token_created_at or item.token_created_at < datetime.utcnow() - timedelta(days=7):
        item.generate_access_token()
        db.session.commit()

    # Подготовка номера
    digits = re.sub(r'\D', '', item.client_phone)
    if digits.startswith('8'):
        digits = '7' + digits[1:]
    elif not digits.startswith('7'):
        digits = '7' + digits

    # Ссылка на PDF с токеном
    pdf_link = url_for('export_pdf_by_token', token=item.access_token, _external=True)

    message = f"Здравствуйте, вот ваша история платежей: {pdf_link}"
    message_encoded = quote(message)
    whatsapp_url = f"https://wa.me/{digits}?text={message_encoded}"

    return redirect(whatsapp_url)


# Все оформленные


@app.route("/contracts")
@login_required
def contracts():
    search_query = request.args.get("q", "").strip()
    created_date_str = request.args.get("created_date", "").strip()

    query = Item.query

    # Фильтрация по текущему пользователю, если не админ
    if not current_user.is_admin:
        query = query.filter(Item.user_id == current_user.id)

    # Поиск по имени клиента, названию товара или имени поручителя
    if search_query:
        query = query.filter(
            or_(
                Item.client_name.ilike(f"%{search_query}%"),
                Item.name.ilike(f"%{search_query}%"),
                Item.guarantor_name.ilike(f"%{search_query}%")
            )
        )

    # Фильтрация по дате оформления
    if created_date_str:
        try:
            created_date = datetime.strptime(created_date_str, "%Y-%m-%d").date()
            query = query.filter(db.func.date(Item.created_at) == created_date)
        except ValueError:
            flash("Неверный формат даты. Используйте ГГГГ-ММ-ДД.", "danger")

    # Сортировка:
    if current_user.is_admin:
        query = query.order_by(Item.created_at.desc())  # Для админа: сначала новые по дате
    else:
        query = query.order_by(Item.user_contract_number.desc())  # Для обычного пользователя: по номеру договора

    # Получаем результат
    items = query.all()

    return render_template(
        "contracts.html",
        items=items,
        search_query=search_query,
        current_date=datetime.today().strftime('%Y-%m-%d')
    )








# Просроченные
@app.route("/overdue")
@login_required
def overdue():
    today = datetime.now().date()
    overdue_items = []

    # Получаем все оформленные товары
    query = Item.query.filter_by(status="Оформлен")
    if not current_user.is_admin:
        query = query.filter(Item.user_id == current_user.id)

    items = query.all()

    for item in items:
        if not item.installments or item.installments <= 0:
            continue  # Пропускаем, если нет рассрочки

        # Определяем start_date
        start_date = None

        # 1. Если указана first_payment_date — используем её
        if hasattr(item, 'first_payment_date') and item.first_payment_date:
            start_date = item.first_payment_date
        else:
            # 2. Иначе берём дату первого платежа + 1 месяц
            first_payment = Payment.query.filter_by(item_id=item.id).order_by(Payment.created_at).first()
            if first_payment:
                start_date = first_payment.created_at.date() + relativedelta(months=1)
            else:
                continue  # Пропускаем, если нет платежей

        if not start_date:
            continue  # Дополнительная проверка (на случай ошибок)

        # Формируем график платежей
        months_total = item.installments
        expected_dates = [start_date + relativedelta(months=i) for i in range(0, months_total)]

        # Получаем оплаченные месяцы
        payments = Payment.query.filter_by(item_id=item.id).all()
        paid_months = set((p.created_at.year, p.created_at.month) for p in payments)

        # Проверяем просрочки
        missed = [
            d for d in expected_dates
            if (today >= d + timedelta(days=1)) and ((d.year, d.month) not in paid_months)
        ]

        if missed:
            item.missed_months = missed
            item.total_months = months_total
            item.payments_made = len(payments)
            item.overdue_months = len(missed)
            item.monthly_payment = round((item.price - item.down_payment) / item.installments, 2)
            overdue_items.append(item)

    return render_template("overdue.html",
                         items=overdue_items,
                         overdue_count=len(overdue_items))
@app.template_filter("ru_month")
def ru_month(value):
    return format_date(value, "LLLL yyyy", locale="ru")  # например: июль 2025
@app.context_processor
def inject_overdue_count():
    if current_user.is_authenticated:
        today = datetime.now().date()
        overdue_count = 0

        # Получаем все товары в статусе "Оформлен"
        query = Item.query.filter_by(status="Оформлен")
        if not current_user.is_admin:
            query = query.filter(Item.user_id == current_user.id)

        items = query.all()

        for item in items:
            if not item.installments or item.installments <= 0:
                continue

            # === Определяем start_date ===
            start_date = None

            # 1. Если указана first_payment_date — используем её
            if hasattr(item, 'first_payment_date') and item.first_payment_date:
                start_date = item.first_payment_date
            else:
                # 2. Иначе берём дату первого платежа + 1 месяц
                first_payment = Payment.query.filter_by(item_id=item.id).order_by(Payment.created_at).first()
                if first_payment:
                    start_date = first_payment.created_at.date() + relativedelta(months=1)
                else:
                    continue  # Пропускаем, если нет платежей

            if not start_date:
                continue  # Дополнительная проверка

            # === Формируем ожидаемые даты платежей ===
            expected_dates = [start_date + relativedelta(months=i) for i in range(item.installments)]

            # === Получаем оплаченные месяцы ===
            payments = Payment.query.filter_by(item_id=item.id).all()
            paid_months = set((p.created_at.year, p.created_at.month) for p in payments if p.created_at)

            # === Проверяем просрочки ===
            for due_date in expected_dates:
                if (today >= due_date + timedelta(days=1)) and ((due_date.year, due_date.month) not in paid_months):
                    overdue_count += 1
                    break  # Достаточно одной просрочки

        return dict(overdue_count=overdue_count)
    else:
        return dict(overdue_count=0)




@app.route("/balance", methods=["GET", "POST"])
@login_required
def user_balance():
    balances = Balance.query.filter_by(user_id=current_user.id).order_by(Balance.created_at.desc()).all()
    investors = Investor.query.filter_by(user_id=current_user.id).all()  # 👈 Добавим список инвесторов
    investors_dict = {inv.id: inv.name for inv in investors}

    if request.method == "POST":
        balance_id = request.form.get("balance_id")
        amount = float(request.form.get("amount", 0))
        name = request.form.get("account_name", "").strip()
        is_default = request.form.get("is_default") == "on"
        investor_id = request.form.get("investor_id")  # 👈 получаем investor_id из формы

        # Если "без инвестора", то None
        investor_id = int(investor_id) if investor_id else None

        if is_default:
            # Убираем статус "основной" у других счетов
            Balance.query.filter(
                Balance.user_id == current_user.id,
                Balance.id != balance_id
            ).update({"is_default": False})
            db.session.flush()

        if balance_id:
            balance = Balance.query.filter_by(id=balance_id, user_id=current_user.id).first()
            if balance:
                balance.amount = amount
                balance.name = name or None
                balance.is_default = is_default
                balance.investor_id = investor_id
        else:
            balance = Balance(
                user_id=current_user.id,
                amount=amount,
                name=name or None,
                is_default=is_default,
                investor_id=investor_id
            )
            db.session.add(balance)

        db.session.commit()
        flash("Счёт сохранён", "success")
        return redirect(url_for("user_balance"))

    return render_template("balance.html", balances=balances, investors=investors,investors_dict=investors_dict)

@app.route("/balance/delete/<int:account_id>")
@login_required
def delete_account(account_id):
    balance = Balance.query.filter_by(id=account_id, user_id=current_user.id).first_or_404()

    if balance.transactions:  # 👈 работает, если у модели есть relationship
        flash("Невозможно удалить счёт — к нему привязаны транзакции.", "danger")
        return redirect(url_for("user_balance"))

    try:
        db.session.delete(balance)
        db.session.commit()
        flash("Счёт удалён", "info")
    except Exception:
        db.session.rollback()
        flash("Произошла ошибка при удалении счёта.", "danger")

    return redirect(url_for("user_balance"))


# Регистрируем кастомный фильтр "mul"
@app.template_filter('mul')
def mul(value, arg):
    return value * arg

# Фильтр для расчёта ежемесячного платежа для страницы проссрочки
@app.template_filter('monthly_payment_calc')
def monthly_payment_calc(item):
    price = item.price or 0
    down_payment = item.down_payment or 0
    installments = item.installments or 1
    return (price - down_payment) / installments





@app.route("/income", methods=["GET", "POST"])
@login_required
def income():
    balances = Balance.query.filter_by(user_id=current_user.id).all()
    if request.method == "POST":
        amount = float(request.form["amount"])
        description = request.form.get("description")
        balance_id = int(request.form.get("balance_id"))

        balance = Balance.query.get(balance_id)
        if balance and balance.user_id == current_user.id:
            transaction = Transaction(
                user_id=current_user.id,
                balance_id=balance_id,
                type="income",
                amount=amount,
                description=description
            )
            balance.amount += amount
            db.session.add(transaction)
            db.session.commit()
            flash("Приход добавлен", "success")
            return redirect(url_for("income"))

    return render_template("income.html", balances=balances)


@app.route("/expense", methods=["GET", "POST"])
@login_required
def expense():
    balances = Balance.query.filter_by(user_id=current_user.id).all()
    if request.method == "POST":
        amount = float(request.form["amount"])
        description = request.form.get("description")
        balance_id = int(request.form.get("balance_id"))

        balance = Balance.query.get(balance_id)
        if balance and balance.user_id == current_user.id:
            transaction = Transaction(
                user_id=current_user.id,
                balance_id=balance_id,
                type="expense",
                amount=amount,
                description=description
            )
            balance.amount -= amount
            db.session.add(transaction)
            db.session.commit()
            flash("Расход добавлен", "success")
            return redirect(url_for("expense"))

    return render_template("expense.html", balances=balances)



@app.route("/transactions")
@login_required
def transactions():
    # Получаем параметры фильтрации
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    type_filter = request.args.get("type")  # 'all', 'income', 'expense', 'payment'

    # Парсим даты
    def parse_date(date_str):
        return dt.strptime(date_str, "%Y-%m-%d") if date_str else None

    start = parse_date(start_date)
    end = parse_date(end_date)
    if end:
        end = (end.replace(hour=23, minute=59, second=59))

    # Фильтрация Transaction
    transaction_query = Transaction.query.filter_by(user_id=current_user.id)
    if start:
        transaction_query = transaction_query.filter(Transaction.created_at >= start)
    if end:
        transaction_query = transaction_query.filter(Transaction.created_at <= end)
    user_transactions = transaction_query.all()

    # Фильтрация Payment
    payment_query = Payment.query.filter_by(user_id=current_user.id, is_deleted=False)
    if start:
        payment_query = payment_query.filter(Payment.created_at >= start)
    if end:
        payment_query = payment_query.filter(Payment.created_at <= end)
    client_payments = payment_query.all()

    # Фильтр по типу
    combined = []

    if type_filter == "income":
        combined = [t for t in user_transactions if t.type == "income"]
    elif type_filter == "expense":
        combined = [t for t in user_transactions if t.type == "expense"]
    elif type_filter == "payment":
        combined = client_payments
    else:  # "all" или нет фильтра
        combined = user_transactions + client_payments

    # Сортируем по дате
    combined.sort(key=lambda x: x.created_at, reverse=False)

    # Подготовка данных для диаграммы
    total_income = sum(t.amount for t in user_transactions if t.type == "income")
    total_expense = sum(t.amount for t in user_transactions if t.type == "expense")
    total_payments = sum(p.amount for p in client_payments)

    chart_data = {
        "labels": ["Платежи клиентов", "Ручной приход", "Расходы"],
        "data": [total_payments, total_income, total_expense],
        "colors": [
            "#198754",  # 💚 success (платежи) — соответствует text-success
            "#0dcaf0",  # 💷 info (приход) — соответствует text-info
            "#dc3545"  # ❤️ danger (расход) — соответствует text-danger
        ]
    }

    return render_template(
        "transactions.html",
        transactions=combined,
        chart_data=chart_data,
        filters={
            "start_date": start_date,
            "end_date": end_date,
            "type": type_filter
        }
    )




@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)








@app.route("/check_clients", methods=["GET", "POST"])
@login_required
def check_clients():
    search_query = request.args.get("q", "").strip()  # Получаем запрос из поисковой формы

    # Стартовый запрос
    query = Item.query  # Используем основной запрос для всех контрактов

    # Если не админ, фильтруем по текущему пользователю
    if not current_user.is_admin:
        query = query.filter(Item.user_id == current_user.id)

    # Если введен поисковый запрос, фильтруем по имени клиента
    if search_query:
        query = query.filter(Item.client_name.ilike(f"%{search_query}%"))

    # Собираем данные из оформленных и просроченных договоров
    contracts = query.all()

    # Дополнительно для просроченных данных
    overdue_items = []
    today = datetime.now().date()

    # Получаем все просроченные элементы
    for item in contracts:
        if item.status == "Оформлен":  # Только оформленные
            first_payment = Payment.query.filter_by(item_id=item.id).filter(Payment.created_at != None).order_by(Payment.created_at).first()
            if not first_payment:
                continue

            start_date = first_payment.created_at.date()

            months_total = item.installments
            expected_dates = [start_date + relativedelta(months=i + 1) for i in range(months_total)]
            payments = Payment.query.filter_by(item_id=item.id).all()
            paid_months = set((p.created_at.year, p.created_at.month) for p in payments if p.created_at)

            past_due_dates = [d for d in expected_dates if today >= d + timedelta(days=1)]

            missed = []
            for d in past_due_dates:
                if (d.year, d.month) not in paid_months:
                    missed.append(d)

            if missed:
                item.missed_months = missed
                item.total_months = months_total
                item.payments_made = len(paid_months)
                item.overdue_months = len(missed)
                item.monthly_payment = round((item.price - item.down_payment) / item.installments)
                overdue_items.append(item)

    return render_template("check_clients.html", contracts=contracts, overdue_items=overdue_items, search_query=search_query)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form.get('name', '').strip()
        current_user.phone = request.form.get('phone', '').strip()
        db.session.commit()
        flash('Данные профиля обновлены', 'success')
    return render_template('profile.html')

# Запуск сервера
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        #app.run(host="127.0.0.1", port=5000, debug=True)  # безопаснее локально
        app.run(host="0.0.0.0", port=8080)





