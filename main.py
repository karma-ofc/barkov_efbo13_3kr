import os
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from pydantic import BaseModel
import secrets
import random
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import jwt
from enum import Enum

# Хеширование паролей напрямую через bcrypt
import bcrypt

# Rate Limiter
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI

# Подключение к БД
from database import get_db_connection

# Get reference to exc_app
exc_app = FastAPI()

# Конфигурация окружения
APP_MODE = os.getenv("APP_MODE", "DEV").upper()
DOCS_USERNAME = os.getenv("DOCS_USERNAME", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "secret")

# Конфигурация JWT
SECRET_KEY = os.getenv("SECRET_KEY", "my_super_secret_key_for_jwt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Проверка допустимых значений режима
if APP_MODE not in ["DEV", "PROD"]:
    raise ValueError(f"Invalid APP_MODE: {APP_MODE}. Must be DEV or PROD.")

app = FastAPI(
    title="FastAPI Application",
    description="Application with authentication",
    version="1.0.0",
    docs_url=None if APP_MODE == "PROD" else "/docs",
    redoc_url=None,  # Всегда отключаем, переопределяем вручную
    openapi_url="/openapi.json",  # Всегда включаем для работы Swagger UI
)

# Инициализация Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests"}
    )

app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

security = HTTPBasic()

# In-memory база пользователей
users_db: Dict[str, dict] = {}

# ==================== Роли пользователей (RBAC) ====================

class Role(str, Enum):
    """Роли пользователей"""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"

# Определение разрешений для каждой роли
ROLE_PERMISSIONS = {
    Role.ADMIN: ["read", "create", "update", "delete"],  # Полные права
    Role.USER: ["read", "update"],                          # Чтение и обновление
    Role.GUEST: ["read"],                                    # Только чтение
}


# ==================== Pydantic модели ====================

class UserBase(BaseModel):
    """Базовая модель пользователя с полем username"""
    username: str


class UserRegister(BaseModel):
    """Модель для регистрации пользователя в SQLite"""
    username: str
    password: str


class TodoCreate(BaseModel):
    """Модель для создания Todo"""
    title: str
    description: str


class TodoUpdate(BaseModel):
    """Модель для обновления Todo"""
    title: str
    description: str
    completed: bool


class Todo(BaseModel):
    """Модель Todo для ответа"""
    id: int
    title: str
    description: str
    completed: bool


class User(UserBase):
    """Модель пользователя для регистрации с паролем и ролью"""
    password: str
    role: Role = Role.USER  # По умолчанию роль user


class UserInDB(UserBase):
    """Модель пользователя для хранения в БД (только хеш пароля)"""
    hashed_password: str
    role: Role = Role.USER  # Роль пользователя


# ==================== Функции работы с паролями ====================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля с использованием защиты от тайминг-атак"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


def get_password_hash(password: str) -> str:
    """Генерация хеша пароля"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


# ==================== Зависимость аутентификации ====================

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    """
    Функция аутентификации, которая:
    - Извлекает учетные данные из заголовка Authorization через Depends
    - Находит пользователя в in-memory базе
    - Проверяет корректность пароля с использованием защиты от тайминг-атак
    - Использует secrets.compare_digest для сравнения логин-строк
    """
    # Используем secrets.compare_digest для защиты от атак по времени
    # при поиске пользователя
    user_found = False
    
    for username, user_data in users_db.items():
        if secrets.compare_digest(username, credentials.username):
            user_found = True
            # Проверяем пароль
            if verify_password(credentials.password, user_data["hashed_password"]):
                return UserBase(username=username)
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Basic"},
                )
    
    if not user_found:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )


# ==================== Защита документации в DEV-режиме ====================

def get_docs_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    """Проверка учетных данных для доступа к документации в DEV-режиме"""
    # Используем secrets.compare_digest для защиты от тайминг-атак
    correct_username = secrets.compare_digest(credentials.username, DOCS_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, DOCS_PASSWORD)
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials for documentation access",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True


# ==================== Кастомные маршруты документации ====================

# Определяем зависимости для документации
docs_dependencies = [Depends(get_docs_credentials)] if APP_MODE == "DEV" else []

@app.get("/docs", dependencies=docs_dependencies, include_in_schema=False)
async def custom_swagger_ui_html():
    """Кастомный эндпоинт для Swagger UI с защитой в DEV-режиме"""
    if APP_MODE == "PROD":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documentation not available in production mode"
        )
    
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title="API Documentation"
    )


@app.get("/redoc", include_in_schema=False)
async def custom_redoc_html():
    """Кастомный эндпоинт для ReDoc (скрыт в DEV-режиме)"""
    if APP_MODE == "PROD":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documentation not available in production mode"
        )
    
    # В DEV-режиме скрываем redoc
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="ReDoc is hidden in DEV mode"
    )


@app.get("/openapi.json", dependencies=docs_dependencies, include_in_schema=False)
async def custom_openapi_json():
    """Кастомный эндпоинт для OpenAPI схемы"""
    if APP_MODE == "PROD":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OpenAPI schema not available in production mode"
        )
    
    return JSONResponse(
        content=app.openapi() if hasattr(app, 'openapi') else {},
        media_type="application/json"
    )


# ==================== Основные маршруты ====================

@app.get("/")
def read_root():
    return {
        "message": "Приложение работает!",
        "mode": APP_MODE,
        "docs_available": APP_MODE == "DEV"
    }


# ==================== Задание 6.1 (базовая аутентификация) ====================

def verify_credentials_from_config(credentials: HTTPBasicCredentials = Depends(security)):
    """Проверка учетных данных из конфига (задание 6.1)"""
    correct_username = secrets.compare_digest(credentials.username, "admin")
    correct_password = secrets.compare_digest(credentials.password, "secret")
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


@app.get("/secure")
def get_secret_message(username: str = Depends(verify_credentials_from_config)):
    return {"message": "Это секретное сообщение! Вы успешно авторизовались.", "user": username}


# ==================== Задание 8.1 (SQLite регистрация) ====================

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register_user_db(user: UserRegister):
    """
    POST-эндпоинт /register для сохранения пользователя в SQLite:
    - Принимает username и password
    - Сохраняет в таблицу users
    - Возвращает success message
    """
    # Подключаемся к базе данных
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Вставляем данные в таблицу users
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (user.username, user.password)
    )
    
    # Фиксируем изменения
    conn.commit()
    
    # Закрываем соединение
    conn.close()
    
    return {"message": "User registered successfully!"}


# ==================== Задание 8.2 (CRUD Todo) ====================

@app.post("/todos", status_code=status.HTTP_201_CREATED, response_model=Todo)
def create_todo(todo: TodoCreate):
    """
    POST /todos - Создание нового Todo
    Принимает title и description, возвращает созданный Todo с completed=False
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO todos (title, description, completed) VALUES (?, ?, ?)",
        (todo.title, todo.description, False)
    )
    
    conn.commit()
    todo_id = cursor.lastrowid
    conn.close()
    
    return {
        "id": todo_id,
        "title": todo.title,
        "description": todo.description,
        "completed": False
    }


@app.get("/todos/{todo_id}", response_model=Todo)
def get_todo(todo_id: int):
    """
    GET /todos/{id} - Получение одного Todo по id
    Возвращает Todo или 404, если не найден
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found"
        )
    
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"],
        "completed": bool(row["completed"])
    }


@app.put("/todos/{todo_id}", response_model=Todo)
def update_todo(todo_id: int, todo: TodoUpdate):
    """
    PUT /todos/{id} - Обновление существующего Todo
    Принимает title, description, completed
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
        (todo.title, todo.description, todo.completed, todo_id)
    )
    
    conn.commit()
    
    # Проверяем, был ли обновлён
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found"
        )
    
    conn.close()
    
    return {
        "id": todo_id,
        "title": todo.title,
        "description": todo.description,
        "completed": todo.completed
    }


@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int):
    """
    DELETE /todos/{id} - Удаление Todo
    Возвращает сообщение об успехе или 404
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    
    conn.commit()
    
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Todo not found"
        )
    
    conn.close()
    
    return {"message": "Todo deleted successfully!"}


@app.get("/protected")
def get_protected_message(current_user: UserBase = Depends(get_current_user)):
    """
    GET-эндпоинт для защищенного контента:
    - Принимает автоматически подставленный current_user через Depends get_current_user
    - Возвращает приветствие с именем пользователя
    """
    return {
        "message": f"Добро пожаловать, {current_user.username}! Это защищенный контент.",
        "user": current_user.username
    }


# ==================== JWT Аутентификация ====================

class Token(BaseModel):
    """Модель ответа с токеном"""
    access_token: str
    token_type: str


class LoginRequest(BaseModel):
    """Модель запроса для логина"""
    username: str
    password: str


def authenticate_user(username: str, password: str) -> bool:
    """
    Гипотетическая функция аутентификации пользователя.
    Использует random.choice для демонстрации (в реальном приложении
    должна проверять по базе данных).
    """
    # Для демонстрации принимаем любые непустые credentials
    return bool(username and password)


def create_access_token(data: dict) -> str:
    """Создание JWT токена"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    """Проверка JWT токена"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_role: str = payload.get("role", "guest")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        return username, user_role
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


def require_role(required_role: Role):
    """Зависимость для проверки роли пользователя"""
    def role_checker(user_data: tuple = Depends(verify_token)):
        username, user_role = user_data
        # Определяем иерархию ролей
        role_hierarchy = {
            Role.ADMIN: 3,
            Role.USER: 2,
            Role.GUEST: 1,
        }
        required_level = role_hierarchy.get(required_role, 0)
        user_level = role_hierarchy.get(Role(user_role), 0)
        # Admin имеет доступ ко всему (уровень 3)
        if user_level >= required_level:
            return username, user_role
        # Проверяем, есть ли у пользователя нужная роль
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Required role: {required_role.value}"
        )
    return role_checker


@app.post("/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, login_data: LoginRequest):
    """
    POST-эндпоинт /login:
    - Если пользователя нет -> 404 Not Found
    - Если пароль неверный -> 401 Unauthorized
    - Иначе возвращает JWT токен
    """
    # Ищем пользователя (с защитой от тайминг-атак)
    user_found = None
    for stored_username, user_data in users_db.items():
        if secrets.compare_digest(stored_username, login_data.username):
            user_found = user_data
            break
    
    if user_found is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Проверяем пароль
    if not verify_password(login_data.password, user_found["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed"
        )
    
    # Генерируем токен
    user_role = user_found.get("role", "user")
    access_token = create_access_token(data={"sub": login_data.username, "role": user_role})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected_resource")
def protected_resource(user_data: tuple = Depends(require_role(Role.USER))):
    """
    GET-эндпоинт /protected_resource:
    - Требует аутентификацию и роль user или admin
    - Возвращает сообщение об успешном доступе
    """
    username, role = user_data
    return {
        "message": f"Вы успешно получили доступ к защищенному ресурсу, {username}!",
        "user": username,
        "role": role
    }


# ==================== RBAC эндпоинты для разных ролей ====================

@app.get("/resources/read")
def read_resources(user_data: tuple = Depends(require_role(Role.GUEST))):
    """
    GET /resources/read - доступно всем ролям (guest, user, admin)
    Только чтение
    """
    username, role = user_data
    return {
        "message": f"Ресурс прочитан пользователем {username} с ролью {role}",
        "permissions": ROLE_PERMISSIONS.get(Role(role), [])
    }


@app.post("/resources/create")
def create_resource(user_data: tuple = Depends(require_role(Role.ADMIN))):
    """
    POST /resources/create - только для admin
    Полные CRUD права
    """
    username, role = user_data
    return {
        "message": f"Ресурс создан администратором {username}",
        "permissions": ROLE_PERMISSIONS[Role.ADMIN]
    }


@app.put("/resources/update")
def update_resource(user_data: tuple = Depends(require_role(Role.USER))):
    """
    PUT /resources/update - для user и admin
    Чтение и обновление
    """
    username, role = user_data
    return {
        "message": f"Ресурс обновлен пользователем {username} с ролью {role}",
        "permissions": ROLE_PERMISSIONS.get(Role(role), [])
    }


@app.delete("/resources/delete")
def delete_resource(user_data: tuple = Depends(require_role(Role.ADMIN))):
    """
    DELETE /resources/delete - только для admin
    Полные права
    """
    username, role = user_data
    return {
        "message": f"Ресурс удален администратором {username}",
        "permissions": ROLE_PERMISSIONS[Role.ADMIN]
    }
