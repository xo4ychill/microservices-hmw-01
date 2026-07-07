"""
Сервис аутентификации (security).

Реализует четыре эндпоинта:
  POST /v1/user               — регистрация нового пользователя
  GET  /v1/user                — информация о текущем пользователе (по токену)
  POST /v1/token                — логин: обмен login/password на JWT
  GET  /v1/token/validation/    — проверка валидности токена (используется
                                   шлюзом через auth_request)

"""

import os
import time

import jwt
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Секрет для подписи JWT берём из переменной окружения, чтобы не хардкодить
# в коде — значение по умолчанию годится только для локальной разработки.
SECRET = os.environ.get("JWT_SECRET", "insecure-dev-secret-change-me")

# Через сколько секунд после выдачи токен перестаёт быть валидным.
TOKEN_TTL_SECONDS = int(os.environ.get("TOKEN_TTL_SECONDS", "3600"))

# login -> хеш пароля (generate_password_hash использует соль + PBKDF2/scrypt
# в зависимости от версии werkzeug, пароль в открытом виде нигде не хранится).
users = {}


def _authorize(req):
    """Общая для нескольких эндпоинтов логика: достать Bearer-токен из
    заголовка Authorization, проверить подпись и срок действия, вернуть
    login владельца токена (или None, если что-то не так).

    Проверяем именно подпись JWT (jwt.decode с указанием алгоритма) — это
    гарантирует, что токен был выдан именно этим сервисом (тем же SECRET),
    а не подделан произвольным клиентом.
    """
    auth_header = req.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):]
    try:
        # jwt.decode сам проверяет "exp" (срок действия) и бросает
        # исключение ExpiredSignatureError, если токен просрочен —
        # оно перехватывается общим except ниже как PyJWTError.
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        return payload.get("sub")  # "sub" (subject) = login пользователя
    except jwt.PyJWTError:
        return None


@app.post("/v1/user")
def register():
    """Регистрация нового пользователя. Анонимный доступ — вызывается
    напрямую через шлюз без auth_request."""
    data = request.get_json(silent=True) or {}
    login = data.get("login")
    password = data.get("password")

    if not login or not password:
        return jsonify({"error": "login and password are required"}), 400

    if login in users:
        # 409 Conflict — семантически корректный код для "уже существует"
        return jsonify({"error": "user already exists"}), 409

    # Пароль в открытом виде нигде не сохраняется — только его хеш.
    users[login] = generate_password_hash(password)
    return jsonify({"login": login}), 201


@app.get("/v1/user")
def get_user():
    """Информация о текущем пользователе. Токен уже был проверен шлюзом
    через auth_request, но сервис всё равно сам расшифровывает его ещё раз,
    чтобы узнать, ЧЕЙ это токен (какой login) — auth_request на стороне
    nginx умеет только сказать "валиден/невалиден", а не вернуть payload
    основному запросу без дополнительной настройки auth_request_set."""
    login = _authorize(request)
    if not login:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"login": login}), 200


@app.post("/v1/token")
def issue_token():
    """Логин: проверяем пару login/password и, если она верна, выдаём
    подписанный JWT со сроком жизни TOKEN_TTL_SECONDS."""
    data = request.get_json(silent=True) or {}
    login = data.get("login")
    password = data.get("password")

    # Намеренно не различаем "пользователь не найден" и "неверный пароль" —
    # единый ответ 401 с общим текстом не даёт злоумышленнику понять,
    # существует ли такой логин в системе (защита от enumeration-атак).
    if not login or not password or login not in users:
        return jsonify({"error": "invalid credentials"}), 401
    if not check_password_hash(users[login], password):
        return jsonify({"error": "invalid credentials"}), 401

    now = int(time.time())
    payload = {
        "sub": login,             # кому выдан токен
        "iat": now,                # issued at — момент выдачи
        "exp": now + TOKEN_TTL_SECONDS,  # expiration — момент истечения
    }
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return jsonify({"token": token}), 200


# Регистрируем оба варианта пути — со слэшем на конце и без — потому что
# в задании путь указан именно с конечным слэшем (/v1/token/validation/),
# а в разных клиентах и прокси это иногда "теряется" в пути.
@app.get("/v1/token/validation")
@app.get("/v1/token/validation/")
def validate_token():
    """Этот эндпоинт вызывается не клиентом напрямую, а шлюзом (auth_request)
    как служебная проверка перед выполнением защищённых маршрутов.
    Возвращает 200 при валидном токене и 401 при отсутствующем/просроченном/
    подделанном — именно код ответа (а не тело) важен для auth_request."""
    login = _authorize(request)
    if not login:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"login": login}), 200


@app.get("/healthz")
def healthz():
    """Технический эндпоинт для проверки живости контейнера
    (можно подключить как healthcheck в docker-compose)."""
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    # Точка входа для локального запуска без gunicorn (например, для
    # быстрой отладки: `python app.py`). В контейнере используется
    # gunicorn — см. Dockerfile.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
