import os
import asyncio
import shutil
import random
import string
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# CONFIG
BOT_TOKEN = "gunakan token bot dari bot father"  # Ganti dengan token dari BotFather
ALLOWED_CHAT = []  # Ganti dengan chat id (integer)

# auth
async def auth(update: Update):
    return update.effective_chat.id in ALLOWED_CHAT

# session helpers
def get_cwd(context):
    s = context.user_data.setdefault("session", {})
    if "cwd" not in s:
        s["cwd"] = os.getcwd()
    return s["cwd"]

def set_cwd(context, newpath):
    s = context.user_data.setdefault("session", {})
    s["cwd"] = newpath

# start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    set_cwd(context, os.getcwd())
    await update.message.reply_text(
        "☑️ Bot aktif!\n\n"
        "📋 Commands:\n"
        "/ls - List directory\n"
        "/cd <folder> - Change directory\n"
        "/download <file> - Download file\n"
        "/nmap <mode> <target> - Port scan\n"
        "/curl <url> - HTTP request\n"
        "/searchsploit <keyword> - Search exploits\n"
        "/dns <domain> - DNS lookup\n"
        "/subfinder <mode> <domain> - Subdomain scan\n"
        "/assetfinder <mode> <domain> - Asset discovery\n"
        "/sslscan <mode> <target> - SSL/TLS audit\n"
        "/httpx <mode> <target> - HTTP probe\n"
        "/screenfetch - System info"
    )

# /ls
async def ls(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    cwd = get_cwd(context)
    try:
        items = os.listdir(cwd)
    except Exception as e:
        return await update.message.reply_text(f"❌ Error: {e}")
    msg = f"📂 Path: {cwd}\n\n"
    if not items:
        msg += "(kosong)"
    else:
        for i in items:
            if os.path.isdir(os.path.join(cwd, i)):
                msg += f"📁 {i}/\n"
            else:
                msg += f"📄 {i}\n"
    await update.message.reply_text(msg)

# /cd
async def cd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if len(context.args) == 0:
        home = os.path.expanduser("~")
        set_cwd(context, home)
        return await update.message.reply_text(f"📂 Pindah ke: {home}")
    cwd = get_cwd(context)
    arg = context.args[0]
    if arg == "..":
        newdir = os.path.dirname(cwd)
    elif arg.startswith("/"):
        newdir = arg
    else:
        newdir = os.path.join(cwd, arg)
    if not os.path.exists(newdir):
        return await update.message.reply_text("❌ Folder tidak ditemukan")
    if not os.path.isdir(newdir):
        return await update.message.reply_text("❌ Bukan folder")
    set_cwd(context, newdir)
    await update.message.reply_text(f"📂 Pindah ke: {newdir}")

# /download
async def download(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if len(context.args) == 0:
        return await update.message.reply_text("Format: /download <file>")
    cwd = get_cwd(context)
    filename = context.args[0]
    path = os.path.join(cwd, filename)
    if not os.path.exists(path):
        return await update.message.reply_text("❌ File tidak ditemukan")
    if os.path.isdir(path):
        return await update.message.reply_text("❌ Itu folder")
    with open(path, "rb") as f:
        await update.message.reply_document(f)

# ---------- helpers ----------
def tool_exists(tool_name):
    return shutil.which(tool_name) is not None

async def run_cmd(cmd, cwd):
    proc = await asyncio.create_subprocess_shell(
        cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    output = ""
    if out:
        output += out.decode(errors="ignore")
    if err:
        output += "\n[ERR]\n" + err.decode(errors="ignore")
    return output.strip() or "(no output)"

async def save_and_send_file(update: Update, context: ContextTypes.DEFAULT_TYPE, output: str, prefix="result"):
    """Save to file, send to Telegram, then DELETE the file"""
    rid = ''.join(random.choices(string.digits, k=6))
    cwd = get_cwd(context)
    filename = f"{prefix}_{rid}.txt"
    filepath = os.path.join(cwd, filename)
    
    # Write file
    with open(filepath, "w") as f:
        f.write(output)
    
    # Send to Telegram
    with open(filepath, "rb") as f:
        await update.message.reply_document(document=f, filename=filename)
    
    # DELETE file setelah dikirim
    try:
        os.remove(filepath)
    except:
        pass
    
    return filename

async def send_long_output(update: Update, context: ContextTypes.DEFAULT_TYPE, output: str, prefix="result"):
    """Send as text if short, else as file (and auto-delete)"""
    if len(output) <= 3500:
        return None
    return await save_and_send_file(update, context, output, prefix)

# ---------------- NMAP ----------------
async def nmap_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if not tool_exists("nmap"):
        return await update.message.reply_text("❌ Nmap tidak ditemukan pada system!")
    if len(context.args) < 2:
        return await update.message.reply_text(
            "Format:\n/nmap <mode> <target>\n\n"
            "Modes:\n"
            "• quick - Fast scan (common ports)\n"
            "• ping - Ping scan only\n"
            "• quickplus - Version detection + OS\n"
            "• traceroute - Trace route to target\n"
            "• intense-noping - Aggressive scan no ping\n"
            "• regular - Standard nmap scan"
        )
    mode = context.args[0].lower()
    target = context.args[1]
    presets = {
        "quick":        f"nmap -T4 -F {target}",
        "ping":         f"nmap -sn {target}",
        "quickplus":    f"nmap -sV -T4 -O -F --version-light {target}",
        "traceroute":   f"nmap -sn --traceroute {target}",
        "intense-noping": f"nmap -T4 -A -v -Pn {target}",
        "regular":      f"nmap {target}",
    }
    if mode not in presets:
        return await update.message.reply_text(f"❌ Mode '{mode}' tidak dikenal")
    cmd = presets[mode]
    msg = await update.message.reply_text(f"🕵️‍♂️ Scan mulai...\nMode: {mode}\nTarget: {target}")
    cwd = get_cwd(context)
    try:
        for percent in [10, 30, 55, 75, 90]:
            await asyncio.sleep(0.4)
            try:
                await msg.edit_text(f"🕵 Sedang scanning… {percent}%\nMode: {mode}\nTarget: {target}")
            except:
                pass
        output = await run_cmd(cmd, cwd)
        saved = await send_long_output(update, context, output, prefix="nmap")
        if saved:
            try:
                await msg.edit_text(f"📄 Scan selesai → file: {saved}")
            except:
                pass
            return
        await msg.edit_text(
            f"🔍 Nmap Result ({mode})\nTarget: `{target}`\n\n```\n{output}\n```",
            parse_mode="Markdown"
        )
    except Exception as e:
        try:
            await msg.edit_text(f"❌ ERROR: {e}")
        except:
            pass

# ---------------- CURL ----------------
async def curl_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if len(context.args) == 0:
        return await update.message.reply_text("Format: /curl <url>")
    url = context.args[0]
    cwd = get_cwd(context)
    msg = await update.message.reply_text(f"🌐 Requesting… {url}")
    cmd = f"curl -L --max-time 20 {url}"
    try:
        output = await run_cmd(cmd, cwd)
        saved = await send_long_output(update, context, output, prefix="curl")
        if saved:
            try:
                await msg.edit_text(f"📄 Output → file: {saved}")
            except:
                pass
            return
        await msg.edit_text(f"🌐 CURL Result\nURL: `{url}`\n\n```\n{output}\n```", parse_mode="Markdown")
    except Exception as e:
        try:
            await msg.edit_text(f"❌ Error: {e}")
        except:
            pass

# ---------------- SEARCHSPLOIT ----------------
async def sploit_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if len(context.args) == 0:
        return await update.message.reply_text("Format: /searchsploit <keyword>")
    keyword = " ".join(context.args)
    cwd = get_cwd(context)
    msg = await update.message.reply_text(f"🔎 Searching exploit: `{keyword}`", parse_mode="Markdown")
    cmd = f"searchsploit {keyword}"
    try:
        output = await run_cmd(cmd, cwd)
        saved = await send_long_output(update, context, output, prefix="exploit")
        if saved:
            try:
                await msg.edit_text(f"📄 Output → file: {saved}")
            except:
                pass
            return
        await msg.edit_text(f"📂 Exploit Result\nKeyword: `{keyword}`\n\n```\n{output}\n```", parse_mode="Markdown")
    except Exception as e:
        try:
            await msg.edit_text(f"❌ Error: {e}")
        except:
            pass

# ---------------- DNS ----------------
async def dns_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if len(context.args) == 0:
        return await update.message.reply_text("Format: /dns <domain>")
    domain = context.args[0]
    cwd = get_cwd(context)
    msg = await update.message.reply_text(f"🌐 Resolving DNS: `{domain}`", parse_mode="Markdown")
    cmd = (
        f"dig {domain} ANY +nocmd +noall +answer; "
        f"dig MX {domain} +short; "
        f"dig NS {domain} +short; "
        f"dig TXT {domain} +short"
    )
    try:
        output = await run_cmd(cmd, cwd)
        saved = await send_long_output(update, context, output, prefix="dns")
        if saved:
            try:
                await msg.edit_text(f"📄 Output → file: {saved}")
            except:
                pass
            return
        await msg.edit_text(f"📡 DNS Result\nDomain: `{domain}`\n\n```\n{output}\n```", parse_mode="Markdown")
    except Exception as e:
        try:
            await msg.edit_text(f"❌ Error: {e}")
        except:
            pass

# ---------------- SUBFINDER ----------------
async def subfinder_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if not tool_exists("subfinder"):
        return await update.message.reply_text("❌ Subfinder tidak ditemukan!")
    if len(context.args) < 2:
        return await update.message.reply_text(
            "Format:\n/subfinder <mode> <domain>\n\n"
            "Modes:\n"
            "• basic - Standard subdomain scan\n"
            "• recursive - Recursive sources only\n"
            "• all-sources - Use all available sources (slow)\n"
            "• silent - Silent mode (subdomains only)"
        )
    mode = context.args[0].lower()
    domain = context.args[1]
    presets = {
        "basic":        f"subfinder -d {domain}",
        "recursive":    f"subfinder -d {domain} -recursive",
        "all-sources":  f"subfinder -d {domain} -all",
        "silent":       f"subfinder -d {domain} -silent",
    }
    if mode not in presets:
        return await update.message.reply_text(f"❌ Mode '{mode}' tidak dikenal")
    
    cmd = presets[mode]
    msg = await update.message.reply_text(f"🔍 Subfinder scan started...\nMode: {mode}\nDomain: {domain}")
    cwd = get_cwd(context)
    
    try:
        for percent in [15, 35, 60, 85]:
            await asyncio.sleep(0.5)
            try:
                await msg.edit_text(f"🔍 Scanning subdomains… {percent}%\nMode: {mode}\nDomain: {domain}")
            except:
                pass
        
        output = await run_cmd(cmd, cwd)
        
        # Always save to file and send (file auto-deleted)
        filename = await save_and_send_file(update, context, output, prefix=f"subfinder_{mode}")
        
        # Count subdomains
        subdomains = [line.strip() for line in output.split('\n') if line.strip() and not line.startswith('[')]
        count = len(subdomains)
        
        try:
            await msg.edit_text(
                f"✅ Subfinder selesai!\n\n"
                f"Mode: {mode}\n"
                f"Domain: `{domain}`\n"
                f"Subdomains found: {count}\n\n"
                f"📄 Result file: {filename}",
                parse_mode="Markdown"
            )
        except:
            pass
            
    except Exception as e:
        try:
            await msg.edit_text(f"❌ Error: {e}")
        except:
            pass

# ---------------- ASSETFINDER ----------------
async def assetfinder_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if not tool_exists("assetfinder"):
        return await update.message.reply_text("❌ Assetfinder tidak ditemukan!")
    if len(context.args) < 2:
        return await update.message.reply_text(
            "Format:\n/assetfinder <mode> <domain>\n\n"
            "Modes:\n"
            "• basic - Find all related domains\n"
            "• subs-only - Subdomains only"
        )
    mode = context.args[0].lower()
    domain = context.args[1]
    presets = {
        "basic":      f"assetfinder {domain}",
        "subs-only":  f"assetfinder --subs-only {domain}",
    }
    if mode not in presets:
        return await update.message.reply_text(f"❌ Mode '{mode}' tidak dikenal")
    
    cmd = presets[mode]
    msg = await update.message.reply_text(f"🎯 Assetfinder scan started...\nMode: {mode}\nDomain: {domain}")
    cwd = get_cwd(context)
    
    try:
        for percent in [20, 50, 80]:
            await asyncio.sleep(0.4)
            try:
                await msg.edit_text(f"🎯 Finding assets… {percent}%\nMode: {mode}\nDomain: {domain}")
            except:
                pass
        
        output = await run_cmd(cmd, cwd)
        
        # Always save to file and send (file auto-deleted)
        filename = await save_and_send_file(update, context, output, prefix=f"assetfinder_{mode}")
        
        # Count results
        assets = [line.strip() for line in output.split('\n') if line.strip()]
        count = len(assets)
        
        try:
            await msg.edit_text(
                f"✅ Assetfinder selesai!\n\n"
                f"Mode: {mode}\n"
                f"Domain: `{domain}`\n"
                f"Assets found: {count}\n\n"
                f"📄 Result file: {filename}",
                parse_mode="Markdown"
            )
        except:
            pass
            
    except Exception as e:
        try:
            await msg.edit_text(f"❌ Error: {e}")
        except:
            pass

# ---------------- SSLSCAN ----------------
async def sslscan_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if not tool_exists("sslscan"):
        return await update.message.reply_text("❌ SSLScan tidak ditemukan!")
    if len(context.args) < 2:
        return await update.message.reply_text(
            "Format:\n/sslscan <mode> <target>\n\n"
            "Modes:\n"
            "• basic - Standard SSL/TLS scan\n"
            "• full - Detailed scan with all ciphers\n"
            "• vulns - Check for vulnerabilities\n"
            "• cert - Certificate details only"
        )
    mode = context.args[0].lower()
    target = context.args[1]
    presets = {
        "basic":   f"sslscan {target}",
        "full":    f"sslscan --show-certificate --show-ciphers {target}",
        "vulns":   f"sslscan --show-certificate --bugs {target}",
        "cert":    f"sslscan --show-certificate --no-ciphersuites {target}",
    }
    if mode not in presets:
        return await update.message.reply_text(f"❌ Mode '{mode}' tidak dikenal")
    
    cmd = presets[mode]
    msg = await update.message.reply_text(f"🔒 SSL scan started...\nMode: {mode}\nTarget: {target}")
    cwd = get_cwd(context)
    
    try:
        for percent in [25, 50, 75]:
            await asyncio.sleep(0.6)
            try:
                await msg.edit_text(f"🔒 Scanning SSL/TLS… {percent}%\nMode: {mode}\nTarget: {target}")
            except:
                pass
        
        output = await run_cmd(cmd, cwd)
        
        # Always save to file and send (file auto-deleted)
        filename = await save_and_send_file(update, context, output, prefix=f"sslscan_{mode}")
        
        try:
            await msg.edit_text(
                f"✅ SSL Scan selesai!\n\n"
                f"Mode: {mode}\n"
                f"Target: `{target}`\n\n"
                f"📄 Result file: {filename}",
                parse_mode="Markdown"
            )
        except:
            pass
            
    except Exception as e:
        try:
            await msg.edit_text(f"❌ Error: {e}")
        except:
            pass

# ---------------- HTTPX ----------------
async def httpx_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if not tool_exists("httpx"):
        return await update.message.reply_text("❌ HTTPx tidak ditemukan!")
    if len(context.args) < 2:
        return await update.message.reply_text(
            "Format:\n/httpx <mode> <target>\n\n"
            "Modes:\n"
            "• basic - Simple HTTP probe\n"
            "• full - Full probe with tech detection\n"
            "• status - Status codes + titles\n"
            "• fast - Fast probe (no extras)"
        )
    mode = context.args[0].lower()
    target = context.args[1]
    presets = {
        "basic":   f"httpx -u {target}",
        "full":    f"httpx -u {target} -tech-detect -status-code -title -web-server",
        "status":  f"httpx -u {target} -status-code -title -content-length",
        "fast":    f"httpx -u {target} -silent -no-color",
    }
    if mode not in presets:
        return await update.message.reply_text(f"❌ Mode '{mode}' tidak dikenal")
    
    cmd = presets[mode]
    msg = await update.message.reply_text(f"🌐 HTTP probe started...\nMode: {mode}\nTarget: {target}")
    cwd = get_cwd(context)
    
    try:
        for percent in [30, 70]:
            await asyncio.sleep(0.3)
            try:
                await msg.edit_text(f"🌐 Probing HTTP… {percent}%\nMode: {mode}\nTarget: {target}")
            except:
                pass
        
        output = await run_cmd(cmd, cwd)
        
        # Always save to file and send (file auto-deleted)
        filename = await save_and_send_file(update, context, output, prefix=f"httpx_{mode}")
        
        try:
            await msg.edit_text(
                f"✅ HTTP Probe selesai!\n\n"
                f"Mode: {mode}\n"
                f"Target: `{target}`\n\n"
                f"📄 Result file: {filename}",
                parse_mode="Markdown"
            )
        except:
            pass
            
    except Exception as e:
        try:
            await msg.edit_text(f"❌ Error: {e}")
        except:
            pass

# ---------------- SCREENFETCH ----------------
async def screenfetch_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    if not tool_exists("screenfetch"):
        return await update.message.reply_text("❌ Screenfetch tidak ditemukan!")
    
    msg = await update.message.reply_text("🖥️ Fetching system info...")
    cwd = get_cwd(context)
    # -N flag: no ASCII art, text only
    cmd = "screenfetch -N"
    
    try:
        output = await run_cmd(cmd, cwd)
        # Send as file to avoid formatting issues
        filename = await save_and_send_file(update, context, output, prefix="sysinfo")
        try:
            await msg.edit_text(f"✅ System Info\n\n📄 File: {filename}")
        except:
            pass
    except Exception as e:
        try:
            await msg.edit_text(f"❌ Error: {e}")
        except:
            pass

# fallback
async def fallback(update: Update, context):
    if not await auth(update):
        return await update.message.reply_text("⛔ Tidak punya izin")
    await update.message.reply_text("❓ Command tidak dikenal")

# main
def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("ls", ls))
    app.add_handler(CommandHandler("cd", cd))
    app.add_handler(CommandHandler("download", download))
    app.add_handler(CommandHandler("nmap", nmap_cmd))
    app.add_handler(CommandHandler("curl", curl_cmd))
    app.add_handler(CommandHandler("searchsploit", sploit_cmd))
    app.add_handler(CommandHandler("dns", dns_cmd))
    app.add_handler(CommandHandler("subfinder", subfinder_cmd))
    app.add_handler(CommandHandler("assetfinder", assetfinder_cmd))
    app.add_handler(CommandHandler("sslscan", sslscan_cmd))
    app.add_handler(CommandHandler("httpx", httpx_cmd))
    app.add_handler(CommandHandler("screenfetch", screenfetch_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, fallback))
    print("🚀 Bot running...")
    app.run_polling()

if __name__ == "__main__":
    main()
