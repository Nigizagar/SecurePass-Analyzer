# SecurePass Analyzer 🛡️

Aplikasi web audit keamanan password canggih yang dirancang menggunakan Flask, Bootstrap 5, dan SQLite. Fokus utama proyek ini adalah menyediakan visualisasi ancaman brute-force dan validasi database kebocoran global Have I Been Pwned secara anonim dan aman (k-Anonymity).

## 🚀 Fitur Unggulan
- **Password Strength Analyzer:** Menilai kekuatan kata sandi secara lokal berdasarkan entropi, struktur, dan kamus pola buruk.
- **k-Anonymity Breach Checker:** Menghitung hash SHA-1 dan hanya mengirimkan 5 karakter pertama ke API luar demi proteksi privasi mutlak.
- **Brute Force Cost Estimator:** Estimasi kalkulasi waktu tebak sandi untuk infrastruktur komputasi CPU, GPU, dan Botnet.
- **Cryptographically Secure Generator:** Membuat password acak kuat berbasis modul `secrets` Python.

## 🛠️ Instalasi & Cara Menjalankan

1. Clone repositori ini:
   ```bash
   git clone https://github.com/Nigizagar/SecurePass-Analyzer.git
   cd SecurePass-Analyzer