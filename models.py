from extensions import db
from flask_login import UserMixin
from datetime import datetime

from sqlalchemy import event


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(128), unique=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(255))
    phone = db.Column(db.String(20), nullable=True)  # например: +7 (999) 123-45-67
    refresh_token = db.Column(db.String, nullable=True)  # Новый токен
    is_active = db.Column(db.Boolean, default=True)
    licenses = db.relationship(
        'License',
        backref='user',
        lazy=True,
        foreign_keys='License.user_id'
    )

    issued_licenses = db.relationship(
        'License',
        backref='issued_by',
        lazy=True,
        foreign_keys='License.activated_by'
    )

    items = db.relationship('Item', backref='user', lazy=True)
    payments = db.relationship('Payment', backref='user', lazy=True)

    def has_valid_license(self):
        now = datetime.utcnow()
        return any(l.is_active and l.expires_at > now for l in self.licenses)

    @property
    def active_license(self):
        now = datetime.utcnow()
        return next(
            (l for l in self.licenses if l.is_active and (l.expires_at is None or l.expires_at > now)),
            None
        )


class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activated_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    activated_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Исправлен тип

    user_contract_number = db.Column(db.Integer, nullable=False)

    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    purchase_price = db.Column(db.Float)
    buyer = db.Column(db.String(100))
    down_payment = db.Column(db.Float, default=0)
    status = db.Column(db.String(20))
    client_name = db.Column(db.String(100))
    client_phone = db.Column(db.String(20))
    guarantor_name = db.Column(db.String(100))
    guarantor_phone = db.Column(db.String(20))
    months = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payments_made = db.Column(db.Integer, default=0)
    installments = db.Column(db.Integer, nullable=False)
    photo_url = db.Column(db.String(255))
    profit_margin = db.Column(db.Float, default=0)
    investor_id = db.Column(db.Integer, db.ForeignKey('investor.id'))
    investor = db.relationship("Investor", backref="items")

    access_token = db.Column(db.String(64), nullable=True, unique=True)
    token_created_at = db.Column(db.DateTime, nullable=True)

    client_address = db.Column(db.String(200), nullable=True)
    first_payment_date = db.Column(db.Date, nullable=True)
    def generate_access_token(self):
        import secrets
        self.access_token = secrets.token_urlsafe(32)
        self.token_created_at = datetime.utcnow()

    STATUS_ACTIVE = 'Активный'
    STATUS_UNPAID = 'unpaid'
    STATUS_PAID = 'paid'
    STATUS_COMPLETED = 'Завершен'

    payments = db.relationship('Payment', backref='item', lazy=True)





class Investor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    profit_percent = db.Column(db.Integer, default=50)  # от 0 до 100

    user = db.relationship("User", backref="investors")

    def __repr__(self):
        return f"<Investor {self.name}>"

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Исправлен тип

    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)





class Balance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=0.0)
    name = db.Column(db.String(50), nullable=True)  # Название счета (необязательное)
    is_default = db.Column(db.Boolean, default=False, nullable=False)  # Основной ли это счет
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow,
                           onupdate=datetime.utcnow, nullable=False)
    investor_id = db.Column(db.Integer, db.ForeignKey("investor.id"), nullable=True)

    investor = db.relationship("Investor", backref="balances")
    # Изменим отношение на uselist=True для поддержки нескольких счетов
    user = db.relationship("User", backref=db.backref("balances", lazy="dynamic"))

    def __repr__(self):
        return f"<Balance {self.id} (User {self.user_id}): {self.amount} {f'({self.name})' if self.name else ''}>"


# Опционально: обработчик для автоматического снятия флага is_default с других счетов
@event.listens_for(Balance, 'before_update')
def before_balance_update(mapper, connection, target):
    if target.is_default:
        # Снимаем флаг is_default со всех других счетов этого пользователя
        Balance.query.filter(
            Balance.user_id == target.user_id,
            Balance.id != target.id,
            Balance.is_default == True
        ).update({'is_default': False})






class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    balance_id = db.Column(db.Integer, db.ForeignKey("balance.id"), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'income' или 'expense'
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="transactions")
    balance = db.relationship("Balance", backref="transactions")