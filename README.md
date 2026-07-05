# 🔐 Xessenger - Secure Peer-to-Peer Messenger

A secure, end-to-end encrypted messaging application for Windows with modern features.

## ✨ Features

- 🔒 **End-to-End Encryption** - All messages encrypted with Diffie-Hellman key exchange + Fernet symmetric encryption
- 🌐 **WebSocket/HTTPS Transport** - Runs over `wss://` (port 443) by default — passes through corporate firewalls and HTTP proxies
- 🎬 **GIF Support** - Search and send GIFs via Tenor integration
- 📎 **File Transfer** - Send files securely to other users
- 💬 **Message Reactions** - React to messages with emojis
- ↩️ **Reply Threading** - Reply to specific messages
- 🔔 **Windows Notifications** - Get notified of new messages even when window is not focused
- 🔐 **Security Verification** - View and verify encryption key fingerprints to prevent MITM attacks
- 🔥 **Self-Destructing Messages** - Optional timed message deletion
- 👀 **Typing Indicators** - See when others are typing
- 🎨 **Color-Coded Users** - Each user gets a unique color for easy identification

## 📋 Requirements

- Windows 10/11
- Python 3.8 or higher
- Internet connection (for GIF search)

## 🚀 Quick Start

### First-Time Setup

1. **Run the Update Script**
   ```batch
   update.bat
   ```
   This will:
   - Check for updates (if using Git)
   - Install all required Python packages
   - Set up the environment

2. **Start the Client**
   ```batch
   python client.py
   ```
   Or simply double-click `client.py` if Python is associated with `.py` files.

3. **Configure Connection**
   - On first run, you'll be prompted for:
     - Server address (e.g., `localhost` or IP address)
     - Server port (default: `5000`)
     - Your nickname
     - Server password (if required)
   
   Settings are saved in `config.json` for future use.

## 🎮 How to Use

### Connecting to a Server

1. Run `client.py`
2. Choose whether to change settings or use saved configuration
3. Enter server password if prompted
4. Wait for connection confirmation

### Sending Messages

- Type your message in the input box
- Press Enter or click "Send"
- Messages are automatically encrypted

### Sending GIFs

1. Click the "🎬 GIF" button
2. Search for a GIF using keywords
3. Click on any GIF to send it

### Sending Files

1. Click the "📎 File" button
2. Select a file from your computer
3. Wait for the recipient to accept
4. File is encrypted and transferred in chunks

### Reacting to Messages

1. Right-click on any message
2. Select "😀 React"
3. Choose an emoji reaction

### Replying to Messages

1. Right-click on any message
2. Select "↩️ Reply to this message"
3. Type your reply
4. Your reply will reference the original message

### Security Features

Click "🔐 Security" to:
- View your encryption key fingerprint
- View peer fingerprints
- Mark keys as trusted
- Verify no MITM attacks

**Important:** Always verify fingerprints with your contacts through another secure channel (phone call, in person) before trusting them!

## ⚙️ Configuration

Settings are stored in `config.json`:

```json
{
    "server_host": "localhost",
    "server_port": 443,
    "nickname": "YourName",
    "use_websocket": true
}
```

- **`use_websocket`** — `true` (default) uses WebSocket over HTTPS (`wss://`), which passes through firewalls. Set to `false` for legacy raw-TCP mode.
- **`server_port`** — use `443` for `wss://`, `80` for `ws://`, or any custom port your server listens on.

> **⚠️ Migration note:** the default port changed from `5000` to `443` when WebSocket support was added.  
> If your server still runs on `5000`, either update the server to listen on `443` (recommended) or set `"server_port": 5000` in `config.json` and `"use_websocket": false`.

You can edit this file manually or use the settings dialog when starting the client.

## 🌐 Firewall-Friendly Transport (WebSocket/HTTPS)

By default Xessenger connects over **WebSocket Secure (`wss://`)**, which piggybacks on the standard HTTPS port (443).  The connection starts as a normal HTTP/1.1 `Upgrade` request and is therefore allowed by:

- Corporate firewalls that only permit HTTP/HTTPS
- Deep-packet-inspection proxies
- Networks that block arbitrary TCP ports

### Server-side requirements

The **server** must be updated to accept WebSocket connections.  Recommended Python server stack:

```bash
pip install websockets
```

```python
import asyncio, json, websockets

async def handler(websocket):
    async for message in websocket:
        packet = json.loads(message)
        # ... route packet as before, reply with websocket.send(json.dumps(...))

async def main():
    async with websockets.serve(handler, "0.0.0.0", 443, ssl=ssl_context):
        await asyncio.Future()  # run forever

asyncio.run(main())
```

All existing JSON packet types (`NICK`, `PUBKEY`, `MSG`, `AUTH`, `FILE_*`, etc.) work unchanged — only the transport layer changes.

### Legacy raw-TCP mode

If your server still uses plain TCP, set `"use_websocket": false` in `config.json` (or answer **No** to the transport dialog at startup).  The client will fall back to the original raw-TCP / TLS path.

## 🔒 Security Features

### Encryption
- **Diffie-Hellman Key Exchange** - Generates unique shared keys for each peer pair
- **Fernet Encryption** - Military-grade AES-128-CBC encryption for all messages
- **SHA-256 Fingerprints** - Verify peer identities

### Trust Model
- **Trust-On-First-Use (TOFU)** - First contact auto-trusts keys
- **Key Change Detection** - Alerts on suspicious key changes
- **Manual Verification** - Verify fingerprints out-of-band

### Privacy
- **No Message Storage** - Server doesn't store messages
- **No Logging** - Messages only in memory
- **Self-Destruct** - Optional message auto-deletion

## 🛠️ Troubleshooting

### "Python not found"
- Install Python from [python.org](https://python.org)
- Make sure to check "Add Python to PATH" during installation

### "Connection refused"
- Ensure the server is running
- Check server IP address and port
- Verify firewall settings

### "No module named X"
- Run `update.bat` to install dependencies
- Or manually: `pip install -r requirements.txt`

### GIFs not loading
- Check internet connection
- Some corporate networks block Tenor
- Try using a different network

### Notifications not working
- Ensure Windows notifications are enabled
- Check notification permissions in Windows Settings

## 📦 Package Contents

- `client.py` - Main client application
- `update.bat` - Setup and update script
- `config.json` - Configuration file (created on first run)
- `trusted_keys.json` - Trusted encryption keys (created automatically)
- `README.md` - This file

## 🐛 Known Issues

- Some antivirus software may flag the application (false positive)
- Large file transfers (>100MB) may be slow
- GIF animations limited to 20 active at once for performance

## 📝 Tips

- **Keyboard Shortcuts:**
  - `Enter` - Send message
  - `Esc` - Cancel reply
  
- **Best Practices:**
  - Always verify fingerprints with trusted contacts
  - Don't share server passwords publicly
  - Use strong, unique nicknames
  
- **Performance:**
  - Clear chat periodically with "🗑️ Clear Chat"
  - Limit number of active GIFs

## 🆘 Support

For issues or questions:
1. Check this README thoroughly
2. Ensure all dependencies are installed (`update.bat`)
3. Check server is running and accessible

## 📜 License

This is a personal/educational project. Use at your own risk.

## ⚠️ Disclaimer

This software is provided "as-is" without warranty. While it implements encryption, it has not been professionally audited. Use for casual communication only, not for highly sensitive data.

---

**Made with ❤️ for secure communication**

Version 1.0 | 2026
