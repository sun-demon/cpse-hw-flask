from flask import (Flask, session, request, jsonify, make_response, Blueprint)
import re
import hashlib
import json
from base64 import b64encode
import os
import sqlite3


connection = sqlite3.connect('sqllite.db', check_same_thread=False)
cursor = connection.cursor()

'''
SQL
'''

def create_tables_if_not_exists():
    cursor.execute('PRAGMA foreign_keys = ON;')

    cursor.execute('''CREATE TABLE IF NOT EXISTS user (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        login TEXT NOT NULL UNIQUE,
                        email TEXT NOT NULL UNIQUE,
                        hash TEXT NOT NULL
                    );''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS newspaper (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        user_id INTEGER REFERENCES user NOT NULL, 
                        message TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES user ON DELETE RESTRICT
                    );''')
    connection.commit()

create_tables_if_not_exists()


'''
Flask
'''

app = Flask(__name__)
bp_auth = Blueprint('auth', __name__, url_prefix='/auth')
bp_news = Blueprint('news', __name__, url_prefix='/news')

users_filepath = 'files/users.json'
news_filepath = 'files/news.json'
app = Flask(__name__, template_folder='templates')
app.secret_key = b'_5#y3L"F4Q8z\n\xec]/'


class User:
    def __init__(self, login_: str, email: str, password: str):
        validate_login(login_)
        validate_email(email)
        validate_password(password)
        self.login = login_
        self.email = email
        self.hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

class Newpaper:
    def __init__(self, login_: str, text: str):
        self.login = login_
        self.text = text

class LoginException(Exception):
    def __init__(self, message):
        super().__init__(message)

class EmailException(Exception):
    def __init__(self, message):
        super().__init__(message)

class PasswordException(Exception):
    def __init__(self, message):
        super().__init__(message)


def has_space(value: str) -> bool:
    return re.search(r'\s', value) is not None

def validate_login(login_: str) -> None:
    MAX_LOGIN_LENGTH = 20
    if login_ == '':
        raise LoginException('Пустое поле')
    elif has_space(login_):
        raise LoginException('Есть пробельные символы')
    elif len(login_) > MAX_LOGIN_LENGTH:
        raise LoginException(f'Длина имени больше {MAX_LOGIN_LENGTH}')

def validate_email(email: str) -> None:
    if not re.fullmatch(r'(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)', email):
        raise EmailException('Неверный формат')

def validate_password(password: str) -> None:
    MIN_PASSWORD_LENGTH = 8
    has_digit = re.search(r'\d', password) is not None
    has_uppercase = re.search(r'[A-Z]', password) is not None
    has_lowercase = re.search(r'[a-z]', password) is not None
    if has_space(password):
        raise PasswordException('Есть пробельные символы')
    elif len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordException(f'Длина пароля меньше {MIN_PASSWORD_LENGTH} символов')
    elif not has_digit:
        raise PasswordException('Нет цифр')
    elif not has_uppercase:
        raise PasswordException('Нет заглавных латинских букв')
    elif not has_lowercase:
        raise PasswordException('Нет строчных латинских букв')


def get_news():
    cursor.execute('''SELECT user.login, newspaper.message 
                      FROM newspaper 
                      LEFT JOIN user 
                      ON newspaper.user_id = user.id ORDER BY newspaper.id;''')
    return list(map(lambda tuple_new: {'login': tuple_new[0], 'text': tuple_new[1]}, cursor.fetchall()))

def login_user(filepath: str, the_user: User):
    cursor.execute('''SELECT user.hash 
                      FROM user 
                      WHERE login = ? 
                      LIMIT 1;''', (the_user.login, ))
    list_hash = cursor.fetchall()
    if len(list_hash) == 0:
        raise LoginException('Неверное имя пользователя')
    elif list_hash[0][0] != the_user.hash:
        raise PasswordException('Неверный пароль')
    salt = b64encode(os.urandom(256)).decode('utf-8')
    session['login'] = the_user.login
    session['salt'] = salt
    result = jsonify({'title': 'news', 'username': the_user.login, 'news': get_news()})
    response = make_response(result)
    response.set_cookie('salt', salt, max_age=15 * 60)
    return response


def register_user(filepath: str, new_user: User):
    cursor.execute('''SELECT login
                      FROM user
                      WHERE user.login = ? OR user.email = ?
                      LIMIT 1;''', (new_user.login, new_user.email))
    users = cursor.fetchall()
    if len(users) != 0:
        if users[0][0] == new_user.login:
            raise LoginException('Этот логин уже занят')
        raise EmailException('Эта почта уже занята')
    cursor.execute('''INSERT INTO user (login, email, hash)
                      VALUES (?, ?, ?);''', (new_user.login, new_user.email, new_user.hash))
    connection.commit()
    salt = b64encode(os.urandom(256)).decode('utf-8')
    session['login'] = new_user.login
    session['salt'] = salt
    result = jsonify({'title': 'news', 'username': new_user.login, 'news': get_news()})
    response = make_response(result)
    response.set_cookie('salt', salt, max_age=15 * 60)
    return response


bp_login = Blueprint('login', __name__)

@app.route('/')
@app.route('/index')
@bp_news.route('/')
def index():
    if session.new or 'salt' not in session or request.cookies.get('salt', None) != session['salt']:
        return {'title': 'login', 'username': '', 'news': []}
    else:
        return {'title': 'news', 'username': session.get('login', None), 'news': get_news()}


@bp_news.route('/add', methods=['POST'])
def add_new():
    if session.new or 'salt' not in session or request.cookies.get('salt', None) != session['salt']:
        return {'title': 'login', 'username': '', 'news': []}
    else:
        cursor.execute('''INSERT INTO newspaper (user_id, message)
                          VALUES ((SELECT id FROM user WHERE user.login = ?), ?);''', (session.get('login', None), request.form.get('text', None)))
        connection.commit()
        return {'title': 'news', 'username': session.get('login', None), 'news': get_news()}


@bp_auth.route('/login', methods=['POST'])
def login():
    try:
        user = User(request.form.get('login', None), 'example@gmail.com', request.form.get('password', None))
        return login_user(users_filepath, user)
    except (LoginException, PasswordException) as err:
        exception_type = 'login' if isinstance(err, LoginException) else 'password'
        return make_response(dict({'error': {
            'class': exception_type,
            'message': str(err)
        }}, ), 401)


@bp_auth.route('/register', methods=['POST'])
def register():
    try:
        new_user = User(request.form.get('login', None), request.form.get('email', None),
                        request.form.get('password', None))
        return register_user(users_filepath, new_user)
    except (LoginException, EmailException, PasswordException) as err:
        exception_type = 'login'
        if isinstance(err, EmailException):
            exception_type = 'email'
        elif isinstance(err, PasswordException):
            exception_type = 'password'
        return make_response(dict({'error': {
            'class': exception_type,
            'message': str(err)
        }}, ), 401)


if __name__ == '__main__':
    app.register_blueprint(bp_auth)
    app.register_blueprint(bp_news)
    app.run(debug=True)
