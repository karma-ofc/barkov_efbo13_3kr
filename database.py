import sqlite3

def get_db_connection():
    """Создание подключения к базе данных SQLite"""
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Создание таблиц users и todos (запустить один раз)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Таблица users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Таблица todos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            completed BOOLEAN NOT NULL DEFAULT 0
        )
    ''')
    
    conn.commit()
    conn.close()
    print("Таблицы users и todos созданы успешно!")

if __name__ == "__main__":
    init_db()
