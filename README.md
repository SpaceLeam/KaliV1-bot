Siap, ini **README.md** versi padat, jelas, dan tidak alay.
Silakan edit kalau perlu tambahan branding.

---

## GitKuroKali — Telegram Remote Pentest Utility

Script ini adalah **bot Telegram berbasis Python** yang memungkinkan eksekusi perintah pentesting dan utilitas sistem secara remote melalui Telegram.
Direkomendasikan untuk dijalankan di **Kali Linux** atau distro Linux lain yang memiliki paket pentest lengkap.

---

## ⚙️ Fitur Utama

* Navigasi file system (`/ls`, `/cd`, `/download`)
* Nmap scanning
* CURL HTTP request
* SearchSploit query
* DNS resolver
* Subdomain enumeration (Subfinder / Assetfinder)
* SSL/TLS Scan (sslscan)
* HTTP probing (httpx)
* System info (`screenfetch`)

---

## 📦 Installation

### Clone dan install dependencies:

```bash
git clone <repo-url>
cd <folder>
pip install -r requirements.txt
```

### Requirements Python

```
python-telegram-bot==21.3
```

### Install tools pendukung (Kali Linux recommended)

```bash
sudo apt update && sudo apt install curl nmap dnsutils screenfetch sslscan exploitdb
```

ProjectDiscovery tools:

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

TomNomNom asset finder:

```bash
go install github.com/tomnomnom/assetfinder@latest
```

Pastikan `$GOPATH/bin` ada di PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## 🔐 Konfigurasi Bot Telegram

Buat bot baru melalui BotFather:

```
/newbot
```

Copy **Bot Token**, lalu buka file:

```python
# CONFIG
BOT_TOKEN = "TOKEN DARI BOTFATHER"
ALLOWED_CHAT = [123456789]  # chat id yg diizinkan
```

### Cara mendapatkan Chat ID Telegram

1. Buka Telegram
2. Cari bot **@userinfobot**
3. Start → akan muncul `id: 123456789`
4. Masukkan angka tersebut ke `ALLOWED_CHAT`

---

## ▶️ Cara Menjalankan

```bash
python GitKuroKali_v1.py
```

Jika berhasil berjalan, bot aktif dan siap menerima command.

---

## 📌 Usage Commands

| Command                        | Deskripsi             |
| ------------------------------ | --------------------- |
| `/start`                       | Info & cek status bot |
| `/ls`                          | List directory        |
| `/cd <folder>`                 | Pindah folder         |
| `/download <file>`             | Download file         |
| `/nmap <mode> <target>`        | Scan port             |
| `/curl <url>`                  | HTTP request          |
| `/searchsploit <keyword>`      | Cari exploit          |
| `/dns <domain>`                | DNS lookup            |
| `/subfinder <mode> <domain>`   | Subdomain scan        |
| `/assetfinder <mode> <domain>` | Asset discovery       |
| `/sslscan <mode> <target>`     | SSL analysis          |
| `/httpx <mode> <target>`       | HTTP probe            |
| `/screenfetch`                 | System info           |

---

## ⚠️ Disclaimer

Gunakan script ini **hanya pada environment legal dan milik sendiri**.
Segala penyalahgunaan berada di luar tanggung jawab pembuat.

---

Kalau mau, gue bisa tambahin:

* installer otomatis (bash install)
* auto detect tools missing
* versi runtime Termux

Mau dibuatkan juga? 🚀
