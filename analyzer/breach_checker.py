import re

def estimate_brute_force(password):
    """
    Mengestimasi waktu yang dibutuhkan untuk membobol password dengan menebak
    kombinasi berdasarkan ruang karakter (Entropy-based estimation).
    """
    if not password:
        return "0 detik"

    length = len(password)
    charset_size = 0

    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'[0-9]', password): charset_size += 10
    if re.search(r'[^A-Za-z0-9]', password): charset_size += 32

    if charset_size == 0:
        charset_size = 10  # Fallback minimum

    # Total kemungkinan kombinasi (Entropy Space)
    combinations = charset_size ** length

    # Definisikan kecepatan tebakan per detik (Kekuatan Komputasi Spekulatif)
    guesses_per_sec_cpu = 10**8      # 100 Juta tebakan/detik (CPU Standard Multi-core)
    guesses_per_sec_gpu = 10**11     # 100 Miliar tebakan/detik (GPU Modern Kelas Atas)
    guesses_per_sec_botnet = 10**13  # 10 Triliun tebakan/detik (Distributed Botnet)

    def format_time(seconds):
        if seconds < 1:
            return "Instan (< 1 detik)"
        
        minutes = seconds / 60
        if minutes < 60:
            return f"{round(minutes, 2)} Menit"
            
        hours = minutes / 60
        if hours < 24:
            return f"{round(hours, 2)} Jam"
            
        days = hours / 24
        if days < 365:
            return f"{round(days, 2)} Hari"
            
        years = days / 365
        if years < 10**6:
            return f"{format(round(years), ',')} Tahun"
        return "Berabad-abad (> 1 Juta Tahun)"

    return {
        "combinations": f"{combinations:.2e}" if combinations > 10**10 else str(combinations),
        "cpu_time": format_time(combinations / guesses_per_sec_cpu),
        "gpu_time": format_time(combinations / guesses_per_sec_gpu),
        "botnet_time": format_time(combinations / guesses_per_sec_botnet)
    }