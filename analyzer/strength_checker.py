import re

def check_password_strength(password):
    """
    Menganalisis kekuatan password berdasarkan panjang, variasi karakter, 
    dan pola umum tanpa menyimpan password itu sendiri secara permanen.
    """
    if not password:
        return {"score": 0, "category": "Very Weak", "feedback": ["Password kosong."]}

    score = 0
    feedback = []
    
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_symbol = bool(re.search(r'[^A-Za-z0-9]', password))

    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 15
    else:
        feedback.append("Password sangat pendek. Gunakan minimal 12-16 karakter.")

    if has_upper: score += 10
    else: feedback.append("Tambahkan huruf besar (A-Z).")
        
    if has_lower: score += 10
    else: feedback.append("Tambahkan huruf kecil (a-z).")
        
    if has_digit: score += 10
    else: feedback.append("Tambahkan angka (0-9).")
        
    if has_symbol: score += 10
    else: feedback.append("Tambahkan simbol/karakter spesial seperti (!, @, #, $, dll).")

    if re.search(r'(123|abc|qwerty|pass)', password.lower()):
        score -= 20
        feedback.append("Terdeteksi pola keyboard atau kata kamus umum ('123', 'abc', 'qwerty', 'pass').")

    if re.search(r'(.)\1{3,}', password):
        score -= 15
        feedback.append("Kurangi penggunaan karakter berulang berturut-turut.")

    score = max(0, min(100, score))

    if score >= 80:
        category = "Very Strong"
    elif score >= 60:
        category = "Strong"
    elif score >= 40:
        category = "Medium"
    elif score >= 20:
        category = "Weak"
    else:
        category = "Very Weak"

    return {
        "length": length,
        "score": score,
        "category": category,
        "feedback": feedback if feedback else ["Password Anda memenuhi standar keamanan modern."],
        "metrics": {
            "has_upper": has_upper,
            "has_lower": has_lower,
            "has_digit": has_digit,
            "has_symbol": has_symbol
        }
    }