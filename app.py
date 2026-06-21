import os
import sys
import re
import sqlite3
import hashlib
import requests
import secrets
import string
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from zoneinfo import ZoneInfo

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'securepass.db')

def init_db():
    """Membuat tabel database secara otomatis jika belum ada."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
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
    """Koneksi standar SQLite yang bersih."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_history_data_wib():
    """Mengambil data riwayat dengan toleransi format tinggi untuk memastikan data selalu tampil."""
    conn = get_db_connection()
    raw_history = conn.execute('SELECT * FROM password_analysis_history ORDER BY checked_at DESC LIMIT 10').fetchall()
    conn.close()
    
    wib_history = []
    for row in raw_history:
        data = dict(row)
        if 'checked_at' in data and data['checked_at']:
            timestamp_str = str(data['checked_at']).strip()
            try:                
                if len(timestamp_str) == 19 and timestamp_str[4] == '-' and timestamp_str[7] == '-':
                    dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    data['checked_at'] = dt.strftime('%d-%m-%Y %H:%M:%S WIB')                
                elif 'WIB' in timestamp_str:
                    pass   
                else:
                    utc_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    utc_time = utc_time.replace(tzinfo=ZoneInfo('UTC'))
                    wib_time = utc_time.astimezone(ZoneInfo('Asia/Jakarta'))
                    data['checked_at'] = wib_time.strftime('%d-%m-%Y %H:%M:%S WIB')
            except Exception as e:
                print(f"Format matching bypassed: {e}")
                data['checked_at'] = timestamp_str
                
        wib_history.append(data)
        
    return wib_history

def check_password_strength(password):
    """Menganalisis kekuatan password berdasarkan kompleksitas struktur."""
    if not password:
        return {"score": 0, "category": "Very Weak", "feedback": ["Password kosong."]}

    score = 0
    feedback = []
    length = len(password)
    
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))

    if length >= 16: score += 40
    elif length >= 12: score += 30
    elif length >= 8: score += 15
    else: feedback.append("Password sangat pendek. Gunakan minimal 12-16 karakter.")

    if has_upper: score += 10
    else: feedback.append("Tambahkan huruf besar (A-Z).")
    if has_lower: score += 10
    else: feedback.append("Tambahkan huruf kecil (a-z).")
    if has_digit: score += 10
    else: feedback.append("Tambahkan angka (0-9).")
    if has_symbol: score += 10
    else: feedback.append("Tambahkan simbol spesial (!, @, #, $, dll).")

    if re.search(r'(123|abc|qwerty|pass)', password.lower()):
        score -= 20
        feedback.append("Terdeteksi pola keyboard/kata kamus umum ('123', 'qwerty', dll).")
    if re.search(r'(.)\1{3,}', password):
        score -= 15
        feedback.append("Kurangi penggunaan karakter berulang berturut-turut.")

    score = max(0, min(100, score))
    if score >= 80: category = "Very Strong"
    elif score >= 60: category = "Strong"
    elif score >= 40: category = "Medium"
    elif score >= 20: category = "Weak"
    else: category = "Very Weak"

    return {"length": length, "score": score, "category": category, "feedback": feedback if feedback else ["Sandi memenuhi standar keamanan modern."]}

def estimate_brute_force(password):
    """Mengestimasi waktu retas berdasarkan ruang entropi karakter."""
    if not password:
        return "0 detik"

    length = len(password)
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'[0-9]', password): charset_size += 10
    if re.search(r'[^A-Za-z0-9]', password): charset_size += 32
    if charset_size == 0: charset_size = 10

    combinations = charset_size ** length
    
    guesses_cpu = 10**8       
    guesses_gpu = 10**11      
    guesses_botnet = 10**13   

    def format_time(seconds):
        if seconds < 1: return "Instan (< 1 detik)"
        minutes = seconds / 60
        if minutes < 60: return f"{round(minutes, 2)} Menit"
        hours = minutes / 60
        if hours < 24: return f"{round(hours, 2)} Jam"
        days = hours / 24
        if days < 365: return f"{round(days, 2)} Hari"
        years = days / 365
        if years < 10**6: return f"{format(round(years), ',')} Tahun"
        return "Berabad-abad (> 1 Juta Tahun)"

    return {
        "combinations": f"{combinations:.2e}" if combinations > 10**10 else str(combinations),
        "cpu_time": format_time(combinations / guesses_cpu),
        "gpu_time": format_time(combinations / guesses_gpu),
        "botnet_time": format_time(combinations / guesses_botnet)
    }

def check_password_breach(password):
    """Pemeriksaan Kebocoran Data menggunakan k-Anonymity HIBP API."""
    if not password:
        return {"is_breached": False, "count": 0}

    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return {"is_breached": False, "count": 0}
        
        hashes = (line.split(':') for line in response.text.splitlines())
        for target_suffix, count in hashes:
            if target_suffix == suffix:
                return {"is_breached": True, "count": int(count)}
        return {"is_breached": False, "count": 0}
    except requests.RequestException:
        return {"is_breached": False, "count": 0}


def generate_secure_password(length=14, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    """Membuat password kriptografis yang aman."""
    charset = ""
    if use_upper: charset += string.ascii_uppercase
    if use_lower: charset += string.ascii_lowercase
    if use_digits: charset += string.digits
    if use_symbols: charset += ("!@#$%^&*()_+-=[]{}|;:,.<>?")
    if not charset: charset = string.ascii_lowercase + string.digits

    password = []
    if use_upper: password.append(secrets.choice(string.ascii_uppercase))
    if use_lower: password.append(secrets.choice(string.ascii_lowercase))
    if use_digits: password.append(secrets.choice(string.digits))
    if use_symbols: password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    remaining_length = length - len(password)
    password += [secrets.choice(charset) for _ in range(remaining_length)]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)

@app.context_processor
def utility_processor():
    return dict(round=round)

init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyzer', methods=['GET', 'POST'])
def analyzer():
    if request.method == 'POST':
        password = request.form.get('password', '')
        strength = check_password_strength(password)
        brute_force = estimate_brute_force(password)
        breach = check_password_breach(password)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        wib_now = datetime.now(ZoneInfo('Asia/Jakarta')).strftime('%Y-%m-%d %H:%M:%S')
        
        cursor.execute('''
            INSERT INTO password_analysis_history (length, score, category, brute_force_duration, checked_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (strength['length'], strength['score'], strength['category'], brute_force['gpu_time'], wib_now))
        
        cursor.execute('''
            INSERT INTO breach_checks (is_breached, breach_count)
            VALUES (?, ?)
        ''', (1 if breach['is_breached'] else 0, breach['count']))
        
        conn.commit()
        conn.close()

        return jsonify({"strength": strength, "brute_force": brute_force, "breach": breach})
    return render_template('analyzer.html')

@app.route('/history')
def history():
    history_data = get_history_data_wib()
    
    conn = get_db_connection()
    stats = conn.execute('SELECT COUNT(*) as total, AVG(score) as avg_score FROM password_analysis_history').fetchone()
    breach_stats = conn.execute('SELECT SUM(is_breached) as breached_total, COUNT(*) as total_checks FROM breach_checks').fetchone()
    conn.close()
    
    return render_template('history.html', history=history_data, stats=stats, breach_stats=breach_stats)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/delete_history/<int:id>', methods=['POST'])
def delete_history(id):
    """Menghapus baris riwayat analisis tertentu berdasarkan ID secara permanen."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        target_id = int(id)
        
        cursor.execute('DELETE FROM password_analysis_history WHERE id = ?', (target_id,))
        
        conn.commit()
        
        if cursor.rowcount > 0:
            return jsonify({"status": "success", "message": "Riwayat berhasil dihapus dari database secara permanen."})
        else:
            return jsonify({"status": "error", "message": "Data tidak ditemukan di database atau sudah terhapus."}), 404
            
    except Exception as e:
        print(f"Database Delete Error: {e}")
        return jsonify({"status": "error", "message": f"Gagal menghapus data: {str(e)}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/clear_all_history', methods=['POST'])
def clear_all_history():
    """Menghapus semua data dari tabel riwayat analisis."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM password_analysis_history')
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "Seluruh log riwayat berhasil dibersihkan!"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Gagal mengosongkan database: {str(e)}"}), 500

@app.route('/generator', methods=['GET', 'POST'])
def generator():
    """Rute untuk menangani pembuatan password kriptografis yang aman."""
    if request.method == 'POST':
        # Mengambil parameter kustomisasi dari frontend (default ke True/14 jika kosong)
        length = int(request.form.get('length', 14))
        use_upper = request.form.get('upper', 'true') == 'true'
        use_lower = request.form.get('lower', 'true') == 'true'
        use_digits = request.form.get('digits', 'true') == 'true'
        use_symbols = request.form.get('symbols', 'true') == 'true'
        
        # Jalankan fungsi generator secure yang sudah Anda miliki di atas
        password_generated = generate_secure_password(
            length=length, 
            use_upper=use_upper, 
            use_lower=use_lower, 
            use_digits=use_digits, 
            use_symbols=use_symbols
        )
        
        # Log pembuatan ke database tabel 'generated_passwords'
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO generated_passwords (length, includes_uppercase, includes_lowercase, includes_numbers, includes_symbols)
                VALUES (?, ?, ?, ?, ?)
            ''', (length, 1 if use_upper else 0, 1 if use_lower else 0, 1 if use_digits else 0, 1 if use_symbols else 0))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database Logging Error (Generator): {e}")

        return jsonify({"password": password_generated})
        
    return render_template('generator.html')

if __name__ == '__main__':
    app.run(debug=True)