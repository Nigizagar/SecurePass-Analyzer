import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'securepass.db')

def init_db():
    """Inisialisasi database dan membuat tabel jika belum ada."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Tabel Riwayat Analisis
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            length INTEGER NOT NULL,
            score INTEGER NOT NULL,
            category TEXT NOT NULL,
            brute_force_duration TEXT NOT NULL,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 2. Tabel Riwayat Generator
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS generated_passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            length INTEGER NOT NULL,
            includes_uppercase INTEGER NOT NULL,
            includes_lowercase INTEGER NOT NULL,
            includes_numbers INTEGER NOT NULL,
            includes_symbols INTEGER NOT NULL,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 3. Tabel Riwayat Pengecekan Kebocoran
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS breach_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            is_breached INTEGER NOT NULL,
            breach_count INTEGER NOT NULL,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Membuka koneksi ke database SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn