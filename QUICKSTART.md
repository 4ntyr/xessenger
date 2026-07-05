# 🚀 Xessenger Quick Start Guide

This guide covers two things:

1. **[Setting up the server](#part-1-server-setup)** — run once by whoever hosts the chat.
2. **[Connecting as a client](#part-2-client-setup)** — for everyone who wants to join.

---

## Part 1: Server Setup

The server is a lightweight Python process that relays encrypted messages between clients.  
It does **not** store or decrypt any messages.

### Requirements

- Linux/macOS/Windows machine with a public IP or hostname
- Python 3.8 or higher
- Open inbound port **115** (or whichever port you choose)

### Step 1 — Install Python dependencies

```bash
pip install websockets cryptography bcrypt
```

### Step 2 — Create an SSL certificate

Clients connect over **wss://** (WebSocket Secure) by default, so the server needs a TLS certificate.

**Option A — Self-signed certificate (easiest, for private use):**

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
    -days 3650 -nodes -subj "/CN=localhost"
```

**Option B — Free CA-signed certificate via Let's Encrypt (recommended for a public server):**

```bash
sudo apt install certbot          # Debian/Ubuntu
sudo certbot certonly --standalone -d your.domain.com
# Certificate: /etc/letsencrypt/live/your.domain.com/fullchain.pem
# Key:         /etc/letsencrypt/live/your.domain.com/privkey.pem
```

> With a CA-signed cert, clients can set `verify_cert = True` inside `client.py` for stricter security.

### Step 3 — Create `server.py`

Create a file called `server.py` in the same directory as your certificates:

```python
import asyncio
import json
import ssl
import websockets

# Optional: require a password before clients can chat
SERVER_PASSWORD = ""   # set to e.g. "s3cr3t" to require authentication

connected_clients = {}   # nickname -> websocket

def make_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("server.crt", "server.key")   # adjust paths as needed
    return ctx

async def broadcast(sender_nick, packet, exclude=None):
    """Relay a packet to every connected client except the excluded one."""
    data = json.dumps(packet)
    targets = [ws for nick, ws in connected_clients.items() if nick != exclude]
    if targets:
        await asyncio.gather(*[ws.send(data) for ws in targets], return_exceptions=True)

async def handler(websocket):
    nickname = None
    authed = not SERVER_PASSWORD   # auto-authenticated when no password is set

    try:
        async for raw in websocket:
            try:
                packet = json.loads(raw)
            except json.JSONDecodeError:
                continue

            ptype = packet.get("type")

            # ── Authentication ────────────────────────────────────────────
            if ptype == "AUTH":
                if packet.get("password") == SERVER_PASSWORD:
                    authed = True
                    await websocket.send(json.dumps({"type": "AUTH_OK"}))
                else:
                    await websocket.send(json.dumps({"type": "AUTH_FAIL"}))
                    await websocket.close()
                    return
                continue

            if not authed:
                await websocket.close()
                return

            # ── Nick registration ─────────────────────────────────────────
            if ptype == "NICK":
                nickname = packet.get("nickname", "Unknown")
                connected_clients[nickname] = websocket
                print(f"[+] {nickname} connected  ({len(connected_clients)} online)")
                # Notify everyone else
                await broadcast(nickname, {"type": "JOIN", "nickname": nickname})
                continue

            # ── Relay everything else to all other clients ─────────────────
            if nickname:
                await broadcast(nickname, packet, exclude=nickname)

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if nickname and nickname in connected_clients:
            del connected_clients[nickname]
            print(f"[-] {nickname} disconnected  ({len(connected_clients)} online)")
            await broadcast(nickname, {"type": "LEAVE", "nickname": nickname})

async def main():
    ssl_ctx = make_ssl_context()
    print("Xessenger server starting on wss://0.0.0.0:115")
    async with websockets.serve(handler, "0.0.0.0", 115, ssl=ssl_ctx):
        await asyncio.Future()   # run forever

asyncio.run(main())
```

> **Plain-WebSocket mode (no TLS):** replace `ssl=ssl_ctx` with `ssl=None` and use port `67`.  
> Clients must then set `"use_websocket": true` and `"server_port": 67` in their `config.json`, and the `wss://` URL becomes `ws://`.

### Step 4 — Open the firewall

Allow inbound TCP on the port you chose (default **115**):

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 115/tcp

# firewalld (RHEL/Fedora)
sudo firewall-cmd --permanent --add-port=115/tcp && sudo firewall-cmd --reload

# AWS/GCP/Azure: add an inbound rule for TCP port 115 in the security group / firewall rules
```

### Step 5 — Start the server

```bash
python server.py
```

You should see:

```
Xessenger server starting on wss://0.0.0.0:115
```

To keep the server running after you close your terminal, use `screen`, `tmux`, or a systemd service:

```bash
# Quick option — run in background with nohup
nohup python server.py &> server.log &
```

---

## Part 2: Client Setup

> **Platform:** Windows 10/11 only (the client uses Windows-specific notification APIs).

### Step 1 — Install Python

1. Download Python 3.8+ from [python.org/downloads](https://python.org/downloads)
2. Run the installer — **check "Add Python to PATH"** ✅
3. Click "Install Now"

### Step 2 — Get Xessenger

**Option A — Git (recommended, enables automatic updates):**

```batch
git clone https://github.com/4ntyr/xessenger.git
cd xessenger
```

**Option B — Download ZIP:**

Download the repository as a ZIP from GitHub, then extract it to a folder such as `C:\Xessenger`.

### Step 3 — Install dependencies

Double-click `update.bat`, or run from a command prompt:

```batch
update.bat
```

Wait until you see **"Setup Complete!"** before continuing.

### Step 4 — Configure the connection

Open (or create) `config.json` in the Xessenger folder and fill in your server details:

```json
{
    "server_host": "your.server.ip.or.hostname",
    "server_port": 115,
    "nickname": "YourName",
    "use_websocket": true
}
```

| Setting | Description |
|---|---|
| `server_host` | IP address or hostname of the server |
| `server_port` | `115` for `wss://`, `67` for `ws://`, `4489` for legacy raw TCP |
| `nickname` | Your display name in the chat |
| `use_websocket` | `true` (default) — uses WebSocket transport; `false` for legacy raw TCP |

Alternatively, skip editing the file and let the client prompt you on first launch.

### Step 5 — Connect

Run the client:

```batch
python client.py
```

1. If prompted to change settings, click **"Yes"** and enter your server details.
2. If the server has a password, you will be asked to enter it.
3. Once connected you'll see **"Connected to server"** in the chat window.

### Step 6 — Start chatting! 💬

| Action | How |
|---|---|
| Send a message | Type in the box at the bottom → press **Enter** or click **Send** |
| Send a GIF | Click **🎬 GIF**, search, click to send |
| Send a file | Click **📎 File**, pick a file, recipient accepts the transfer |
| React to a message | Right-click a message → **😀 React** |
| Reply to a message | Right-click a message → **↩️ Reply** |
| Verify encryption keys | Click **🔐 Security** — compare fingerprints out-of-band (phone call, in person) |

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Python not found` | Reinstall Python and check "Add Python to PATH"; restart your PC |
| `Connection refused` | Confirm the server is running and the port is open on the firewall |
| `No module named X` | Run `update.bat` again with an active internet connection |
| GIFs not loading | Corporate networks sometimes block Tenor; try another network |
| Notifications not working | Check Windows notification permissions in **Settings → System → Notifications** |

---

## Security Tips

- 🔒 **Verify fingerprints** — after connecting, click **🔐 Security** and confirm your peers' key fingerprints via a phone call or in person.  This prevents man-in-the-middle attacks.
- 🔑 **Use a server password** — set `SERVER_PASSWORD` in `server.py` to restrict who can join.
- 📜 **Use a CA-signed cert** — avoids relying on "trust on first use" for the TLS layer.

---

**That's it — enjoy secure messaging! 🎉**
