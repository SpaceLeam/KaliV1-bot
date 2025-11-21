

## 📄 README.md

````markdown
# GitKuroKali — Telegram Remote Pentest Utility

Script ini adalah bot Telegram berbasis Python yang memungkinkan eksekusi command pentesting dan utilitas sistem secara remote melalui Telegram.  
Direkomendasikan untuk dijalankan di **Kali Linux** atau distro Linux lain yang mendukung tools security.

---

## ⚙️ Fitur Utama
- Navigasi filesystem (`/ls`, `/cd`, `/download`)
- Nmap scanning
- CURL HTTP request
- SearchSploit query
- DNS lookup
- Subdomain enumeration (Subfinder / Assetfinder)
- SSL/TLS scanning (sslscan)
- HTTP probing (httpx)
- System info (`screenfetch`)

---

## 📦 Installation

### Clone repo & install dependencies
```bash
git clone <repo-url>
cd <folder>
pip install -r requirements.txt
````

### Requirements Python

```
python-telegram-bot==21.3
```

### Install supporting tools (recommended: Kali Linux)

```bash
sudo apt update && sudo apt install curl nmap dnsutils screenfetch sslscan exploitdb
```

ProjectDiscovery tools:

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Asset finder:

```bash
go install github.com/tomnomnom/assetfinder@latest
```

Add to PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## 🔐 Konfigurasi Bot Telegram

Buat bot via **BotFather**

```
/newbot
```

Copy **Bot Token**, lalu edit file:

```python
BOT_TOKEN = "TOKEN DARI BOTFATHER"
ALLOWED_CHAT = [123456789]  # chat id yang diperbolehkan
```

### Cara mendapatkan Chat ID Telegram

1. Buka Telegram
2. Cari bot **@userinfobot**
3. `/start` → muncul `id: 123456789`
4. Masukkan ke `ALLOWED_CHAT`

---

## ▶️ Menjalankan Script

```bash
python GitKuroKali_v1.py
```

---

## 📌 Command Usage

| Command                        | Fungsi             |
| ------------------------------ | ------------------ |
| `/start`                       | Informasi bot      |
| `/ls`                          | List directory     |
| `/cd <folder>`                 | Pindah directory   |
| `/download <file>`             | Download file      |
| `/nmap <mode> <target>`        | Port scanning      |
| `/curl <url>`                  | HTTP request       |
| `/searchsploit <keyword>`      | Cari exploit       |
| `/dns <domain>`                | DNS resolver       |
| `/subfinder <mode> <domain>`   | Subdomain scan     |
| `/assetfinder <mode> <domain>` | Asset discovery    |
| `/sslscan <mode> <target>`     | SSL Security Check |
| `/httpx <mode> <target>`       | HTTP probing       |
| `/screenfetch`                 | System info        |

---

## 📷 Screenshot Setup

![Telegram Setup](tele2.png)
![Telegram Token Example](tele.png)

---

## ⚠️ Disclaimer

Gunakan hanya untuk testing legal di environment sendiri.
Segala bentuk penyalahgunaan di luar tanggung jawab pembuat.
