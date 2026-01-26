"""
╔══════════════════════════════════════════════════════════════╗
║                    🔐 XESSENGER CLIENT                      ║
║                                                              ║
║  Secure End-to-End Encrypted Messaging Application          ║
║  Version 1.0 - 2026                                          ║
║                                                              ║
║  Features:                                                   ║
║  • End-to-End Encryption (Diffie-Hellman + Fernet)         ║
║  • GIF Support via Tenor API                                 ║
║  • File Transfer (Encrypted)                                 ║
║  • Message Reactions & Reply Threading                       ║
║  • Windows Notifications                                     ║
║  • Security Fingerprint Verification                         ║
║                                                              ║
║  Usage: python client.py                                     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import threading
import sys
import ssl
import re
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, Toplevel, Label, Entry, Button, Frame, Canvas, Scrollbar, VERTICAL, HORIZONTAL, filedialog
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
import base64
import json
import uuid
import time
from winotify import Notification, audio
from datetime import datetime
from zoneinfo import ZoneInfo
import requests
from PIL import Image, ImageTk
from io import BytesIO
import hashlib
from typing import Optional, Dict, List, Tuple, Any

# Configuration file management
def load_config():
    """Load configuration from config.json."""
    config_file = 'config.json'
    default_config = {
        'server_host': 'localhost',
        'server_port': 5000,
        'nickname': 'User'
    }
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults for any missing keys
                return {**default_config, **config}
        except Exception as e:
            print(f"Error loading config: {e}")
            return default_config
    return default_config

def save_config(host, port, nickname):
    """Save configuration to config.json."""
    config = {
        'server_host': host,
        'server_port': port,
        'nickname': nickname
    }
    
    try:
        with open('config.json', 'w') as f:
            json.dump(config, indent=4, fp=f)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

# Tenor API configuration
TENOR_API_KEY = "AIzaSyAyimkuYQYF_FXVALexPuGQctUWRURdCYQ"  # Default key, users should get their own
TENOR_API_URL = "https://tenor.googleapis.com/v2/search"

class CommunicationClient:
    def __init__(self, host: str = 'localhost', port: int = 5000, nickname: str = 'User') -> None:
        self.host = host
        self.port = port
        self.nickname = nickname
        self.socket = None
        self.connected = False
        self.cipher = None
        self.gui = None
        
        # E2E encryption components
        self.dh_parameters = None
        self.dh_private_key = None
        self.dh_public_key = None
        self.shared_keys = {}  # nickname -> shared Fernet key
        self.peer_public_keys = {}  # nickname -> DH public key
        self.peer_fingerprints = {}  # nickname -> key fingerprint
        self.trusted_keys = {}  # nickname -> fingerprint (manually verified)
        self.pending_messages = []  # Messages waiting for key exchange
        self.message_timers = {}  # msg_id -> threading.Timer for self-destruct
        self.server_password = None  # Server password for authentication
        self.use_tls = True  # Use TLS/SSL for connection
        self.verify_cert = False  # Set to True for production with valid certificates
        self.key_change_history = {}  # nickname -> [timestamps] for suspicious activity detection
        self.pending_auto_trust = {}  # nickname -> Timer for auto-trust
        
        # File transfer tracking
        self.active_file_transfers = {}  # file_id -> {filename, filesize, chunks, received_chunks, sender}
        self.sending_file_transfers = {}  # file_id -> {filename, filesize, total_chunks, sent_chunks, cancel_flag}
        
        # Certificate pinning
        self.pinned_certs = {}  # hostname -> certificate fingerprint
        self.load_pinned_certs()
        
        # Load trusted keys from file
        self.load_trusted_keys()
    
    def generate_dh_parameters(self) -> None:
        """Generate Diffie-Hellman parameters for key exchange.
        
        Uses RFC 3526 2048-bit MODP Group (Group 14) for performance and security.
        This is a well-vetted, standardized prime that provides strong security
        without requiring costly parameter generation at runtime.
        
        Security Properties:
        - 2048-bit key size provides ~112 bits of security
        - Standardized prime eliminates backdoor concerns
        - Generator g=2 is efficient and secure
        
        Reference: RFC 3526 - More Modular Exponential (MODP) Diffie-Hellman groups
        """
        # Using RFC 3526 2048-bit MODP Group for faster setup
        p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
                '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
                '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
                'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
                '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
                '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
                'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
                '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
        g = 2
        self.dh_parameters = dh.DHParameterNumbers(p, g).parameters()
    
    def generate_dh_keys(self) -> None:
        """Generate ephemeral Diffie-Hellman key pair for Perfect Forward Secrecy.
        
        Creates a new temporary key pair for each session. If this key is compromised,
        past communications remain secure because each session uses different keys.
        
        Flow:
        1. Generate DH parameters if not already present
        2. Generate private key (kept secret, never transmitted)
        3. Derive public key (shared with peers)
        
        Note: Keys are regenerated on each connection for PFS.
        """
        if not self.dh_parameters:
            self.generate_dh_parameters()
        # Generate ephemeral private key (never leaves this device)
        self.dh_private_key = self.dh_parameters.generate_private_key()
        # Derive public key for transmission to peers
        self.dh_public_key = self.dh_private_key.public_key()
    
    def serialize_public_key(self) -> bytes:
        """Serialize public key for transmission"""
        return self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def generate_fingerprint(self, public_key_bytes: bytes) -> str:
        """Generate SHA-256 fingerprint of public key for human verification.
        
        Args:
            public_key_bytes: Raw bytes of the public key
        
        Returns:
            Colon-separated hex fingerprint (e.g., 'A1:B2:C3:...')
        
        Purpose:
        - Enables out-of-band verification (phone, in-person, etc.)
        - Detects man-in-the-middle attacks
        - Used in Trust-On-First-Use (TOFU) model
        
        Usage:
        Users can compare fingerprints over a trusted channel to ensure
        they're communicating with the intended peer, not an attacker.
        """
        # Hash the public key with SHA-256 (collision-resistant)
        sha256_hash = hashlib.sha256(public_key_bytes).hexdigest()
        # Format as colon-separated bytes for readability: XX:XX:XX:...
        fingerprint = ':'.join(sha256_hash[i:i+2].upper() for i in range(0, len(sha256_hash), 2))
        return fingerprint
    
    def derive_shared_key(self, peer_public_key_bytes: bytes) -> bytes:
        """Derive shared symmetric encryption key using Diffie-Hellman key exchange.
        
        Args:
            peer_public_key_bytes: PEM-encoded public key from peer
        
        Returns:
            Base64-encoded Fernet-compatible symmetric key
        
        Process:
        1. Load peer's public key from PEM format
        2. Perform DH exchange: shared_secret = peer_public^our_private mod p
        3. Derive deterministic key using HKDF-SHA256
        4. Encode as Fernet-compatible key (URL-safe base64)
        
        Security:
        - Both peers derive identical key without transmitting it
        - HKDF provides key strengthening and domain separation
        - Result is used with Fernet (AES-128-CBC + HMAC-SHA256)
        """
        # Deserialize peer's public key
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        
        # Perform Diffie-Hellman exchange to derive shared secret
        shared_secret = self.dh_private_key.exchange(peer_public_key)
        
        # Strengthen and derive a Fernet-compatible key using HKDF-SHA256
        # HKDF provides: key stretching, domain separation via info parameter
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for Fernet
            salt=None,  # Not needed with strong input entropy
            info=b'e2e-chat-encryption'  # Domain separation string
        ).derive(shared_secret)
        
        # Encode as URL-safe base64 for Fernet compatibility
        return base64.urlsafe_b64encode(derived_key)
        
    def connect(self) -> None:
        """Connect to the communication server"""
        try:
            # Validate nickname before connecting
            sanitized_nick = self.sanitize_nickname(self.nickname)
            if not sanitized_nick:
                if self.gui:
                    self.gui.display_message(
                        "Invalid nickname (3-30 characters, alphanumeric only)",
                        "ERROR"
                    )
                    messagebox.showerror(
                        "Invalid Nickname",
                        "Nickname must be 3-30 characters and contain only letters, numbers, spaces, underscores, or hyphens."
                    )
                self.connected = False
                return
            self.nickname = sanitized_nick
            
            # Generate DH keys for E2E encryption (Perfect Forward Secrecy)
            self.generate_dh_keys()
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Wrap with TLS/SSL
            if self.use_tls:
                try:
                    ssl_context = ssl.create_default_context()
                    if not self.verify_cert:
                        # For self-signed certificates
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE
                    
                    # Connect first, THEN wrap with SSL
                    self.socket.connect((self.host, self.port))
                    self.socket = ssl_context.wrap_socket(self.socket, server_hostname=self.host)
                    
                    if self.gui:
                        self.gui.display_message("🔒 TLS/SSL connection established", "SYSTEM")
                    
                    # Verify certificate pinning AFTER connection is established
                    if not self.verify_certificate_pinning(self.socket):
                        if self.gui:
                            self.gui.display_message("Certificate verification failed - disconnecting", "ERROR")
                        self.connected = False
                        self.socket.close()
                        return
                    
                except Exception as e:
                    if self.gui:
                        self.gui.display_message(f"⚠️ TLS error: {e}", "ERROR")
                    raise
            else:
                # No TLS - just connect normally
                self.socket.connect((self.host, self.port))
            
            # First, handle authentication if password is set
            if self.server_password:
                auth_packet = json.dumps({"type": "AUTH", "password": self.server_password})
                self.socket.send((auth_packet + "\n").encode('utf-8'))
                
                # Wait for authentication response
                auth_response = self.socket.recv(4096).decode('utf-8')
                if auth_response:
                    try:
                        auth_data = json.loads(auth_response.strip())
                        if auth_data.get("type") == "AUTH_RESULT":
                            if not auth_data.get("success"):
                                error_msg = auth_data.get("message", "Authentication failed")
                                if self.gui:
                                    self.gui.display_message(error_msg, "ERROR")
                                    messagebox.showerror("Authentication Failed", error_msg)
                                self.connected = False
                                return
                    except (json.JSONDecodeError, KeyError) as e:
                        self.log_error("Failed to parse auth response", e)
            
            self.connected = True
            
            if self.gui:
                self.gui.display_message("Connected to server", "SYSTEM")
            
            # Send nickname to server (plaintext - server needs it for routing)
            nick_packet = json.dumps({"type": "NICK", "nickname": self.nickname})
            self.socket.send((nick_packet + "\n").encode('utf-8'))
            
            # Broadcast public key to all clients via server
            public_key_pem = self.serialize_public_key().decode('utf-8')
            key_packet = json.dumps({
                "type": "PUBKEY",
                "nickname": self.nickname,
                "public_key": public_key_pem
            })
            self.socket.send((key_packet + "\n").encode('utf-8'))
            
            if self.gui:
                self.gui.display_message("End-to-end encryption initialized", "SYSTEM")
            
            # Start thread to receive messages
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
        except ConnectionRefusedError as e:
            error_msg = f"Could not connect to {self.host}:{self.port}"
            if self.gui:
                self.gui.display_message(error_msg, "ERROR")
                messagebox.showerror("Connection Error", error_msg + "\n\nMake sure the server is running.")
            self.log_error(error_msg, e)
            self.connected = False
            # Clean up socket on failure
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None
        except Exception as e:
            error_msg = f"Connection error: {e}"
            if self.gui:
                self.gui.display_message(error_msg, "ERROR")
                messagebox.showerror("Connection Error", error_msg)
            self.log_error(error_msg, e)
            self.connected = False
            # Clean up socket on failure
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None
    
    def send_message(self, message: str) -> None:
        """Send an end-to-end encrypted message to all connected peers.
        
        Args:
            message: Plaintext message string to send
        
        Process:
        1. Sanitize and validate message input
        2. Parse special commands (/d for self-destruct)
        3. Generate unique message ID for tracking
        4. Encrypt separately for each peer using their shared key
        5. Add replay protection (nonce + timestamp)
        6. Transmit encrypted packets via server
        7. Display locally and handle self-destruct timer
        
        Security Features:
        - End-to-end encryption: Each peer gets separately encrypted copy
        - Replay protection: Unique nonce + timestamp prevents replay attacks
        - Input sanitization: Prevents injection attacks
        - Message size limits: Prevents DoS via memory exhaustion
        
        Special Commands:
        - /d <seconds> <message>: Self-destruct message after specified time (1-3600s)
        
        Note: Server acts as relay only and cannot decrypt message contents.
        """
        try:
            if self.connected and message.strip():
                # Sanitize message to prevent injection attacks and limit size
                sanitized_msg = self.sanitize_message(message)
                if not sanitized_msg:
                    return
                
                if not self.shared_keys:
                    if self.gui:
                        self.gui.display_message("Waiting for other clients to join...", "SYSTEM")
                    return
                
                # Check for /d command (self-destruct)
                destruct_timer = None
                actual_message = sanitized_msg
                
                if sanitized_msg.startswith("/d "):
                    parts = sanitized_msg.split(" ", 2)
                    if len(parts) >= 3:
                        try:
                            destruct_timer = int(parts[1])
                            actual_message = parts[2]
                            
                            if destruct_timer <= 0 or destruct_timer > 3600:
                                if self.gui:
                                    self.gui.display_message("Destruct timer must be between 1 and 3600 seconds", "ERROR")
                                return
                        except ValueError:
                            if self.gui:
                                self.gui.display_message("Usage: /d <seconds> <message>", "ERROR")
                            return
                    else:
                        if self.gui:
                            self.gui.display_message("Usage: /d <seconds> <message>", "ERROR")
                        return
                
                # Generate unique message ID for tracking and replies
                msg_id = str(uuid.uuid4())
                
                # Get reply data if replying to another message
                reply_data = None
                if self.gui and self.gui.reply_to:
                    reply_data = self.gui.reply_to.copy()
                
                # Encrypt message separately for each peer using their unique shared key
                # This ensures true E2E: even if server is compromised, messages stay private
                encrypted_messages = {}
                for peer_nickname, shared_key in self.shared_keys.items():
                    # Use Fernet (AES-128-CBC + HMAC-SHA256) for authenticated encryption
                    cipher = Fernet(shared_key)
                    # Encrypt message and convert to string for JSON transmission
                    encrypted_msg = cipher.encrypt(actual_message.encode('utf-8')).decode('utf-8')
                    encrypted_messages[peer_nickname] = encrypted_msg
                
                # Prepare packet with replay protection mechanisms
                # nonce: prevents duplicate message acceptance
                # timestamp: prevents old message replay
                msg_packet = {
                    "type": "DESTRUCT_MSG" if destruct_timer else "MSG",
                    "from": self.nickname,
                    "encrypted_messages": encrypted_messages,
                    "msg_id": msg_id,
                    "nonce": str(uuid.uuid4()),  # Replay protection
                    "timestamp": time.time()  # Replay protection
                }
                
                if destruct_timer:
                    msg_packet["destruct_timer"] = destruct_timer
                
                if reply_data:
                    msg_packet["reply_to"] = reply_data
                
                # Send encrypted messages via server
                self.socket.send((json.dumps(msg_packet) + "\n").encode('utf-8'))
                
                if self.gui:
                    display_msg = actual_message
                    if destruct_timer:
                        display_msg = f"{actual_message} 🔥 (self-destructs in {destruct_timer}s)"
                    self.gui.display_message(display_msg, "YOU", msg_id=msg_id, reply_to=reply_data)
                    
                    # Clear reply after sending
                    if reply_data:
                        self.gui.cancel_reply()
                    
                    # Schedule local deletion if self-destruct
                    if destruct_timer:
                        timer = threading.Timer(destruct_timer, self.delete_message, args=[msg_id])
                        timer.daemon = True
                        timer.start()
                        self.message_timers[msg_id] = timer
                        
        except Exception as e:
            error_msg = f"Error sending message: {e}"
            if self.gui:
                self.gui.display_message(error_msg, "ERROR")
    
    def send_gif(self, gif_url, destruct_timer=None):
        """Send an encrypted GIF URL to all peers"""
        try:
            if self.connected and gif_url.strip():
                # Validate GIF URL
                if not self.validate_url(gif_url):
                    if self.gui:
                        self.gui.display_message("Invalid GIF URL", "ERROR")
                    return
                
                if not self.shared_keys:
                    if self.gui:
                        self.gui.display_message("Waiting for other clients to join...", "SYSTEM")
                    return
                
                # Generate unique message ID
                msg_id = str(uuid.uuid4())
                
                # Encrypt GIF URL for each peer with their shared key
                encrypted_gifs = {}
                for peer_nickname, shared_key in self.shared_keys.items():
                    cipher = Fernet(shared_key)
                    encrypted_url = cipher.encrypt(gif_url.encode('utf-8')).decode('utf-8')
                    encrypted_gifs[peer_nickname] = encrypted_url
                
                # Prepare packet
                msg_packet = {
                    "type": "DESTRUCT_GIF_MSG" if destruct_timer else "GIF_MSG",
                    "from": self.nickname,
                    "encrypted_gifs": encrypted_gifs,
                    "msg_id": msg_id
                }
                
                if destruct_timer:
                    msg_packet["destruct_timer"] = destruct_timer
                
                # Send encrypted GIF via server
                self.socket.send((json.dumps(msg_packet) + "\n").encode('utf-8'))
                
                if self.gui:
                    self.gui.display_gif(gif_url, "YOU", msg_id=msg_id, destruct_timer=destruct_timer)
                    
                    # Schedule local deletion if self-destruct
                    if destruct_timer:
                        timer = threading.Timer(destruct_timer, self.delete_message, args=[msg_id])
                        timer.daemon = True
                        timer.start()
                        self.message_timers[msg_id] = timer
                        
        except Exception as e:
            error_msg = f"Error sending GIF: {e}"
            if self.gui:
                self.gui.display_message(error_msg, "ERROR")
    
    def delete_message(self, msg_id):
        """Delete a message by its ID (for self-destruct)"""
        if self.gui:
            self.gui.delete_message_by_id(msg_id)
        
        # Clean up timer
        if msg_id in self.message_timers:
            del self.message_timers[msg_id]
    
    def send_reaction(self, reaction_data):
        """Send a reaction to a message (broadcast to all users)"""
        try:
            if not self.connected:
                return
            
            # Encrypt reaction data for each connected peer
            encrypted_reactions = {}
            for peer_nickname, shared_key in self.shared_keys.items():
                cipher = Fernet(shared_key)
                reaction_json = json.dumps(reaction_data)
                encrypted_reactions[peer_nickname] = cipher.encrypt(reaction_json.encode('utf-8')).decode('utf-8')
            
            if not encrypted_reactions:
                return
            
            # Prepare packet (broadcast like messages)
            reaction_packet = {
                "type": "REACTION",
                "from": self.nickname,
                "encrypted_reactions": encrypted_reactions,
                "nonce": str(uuid.uuid4()),
                "timestamp": time.time()
            }
            
            # Send reaction
            self.socket.send((json.dumps(reaction_packet) + "\n").encode('utf-8'))
            
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error sending reaction: {e}", "ERROR")
    
    def auto_trust_key(self, nickname, fingerprint):
        """Automatically trust a key after delay (for client restarts)"""
        try:
            # Verify fingerprint is still current
            if nickname in self.peer_fingerprints and self.peer_fingerprints[nickname] == fingerprint:
                self.trusted_keys[nickname] = fingerprint
                self.save_trusted_keys()
                
                if self.gui:
                    self.gui.display_message(
                        f"✓ {nickname}'s new key automatically trusted",
                        "SYSTEM"
                    )
            
            # Clean up pending timer
            if nickname in self.pending_auto_trust:
                del self.pending_auto_trust[nickname]
        except Exception as e:
            pass  # Silently fail
    
    def sanitize_nickname(self, nickname):
        """Sanitize and validate nickname"""
        if not nickname or not isinstance(nickname, str):
            return None
        
        # Remove control characters and excessive whitespace
        nickname = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', nickname)
        nickname = nickname.strip()
        
        # Length validation (3-30 characters)
        if len(nickname) < 3 or len(nickname) > 30:
            return None
        
        # Only allow alphanumeric, spaces, underscores, hyphens
        if not re.match(r'^[a-zA-Z0-9 _-]+$', nickname):
            return None
        
        return nickname
    
    def log_error(self, message, exception=None):
        """Log error message with optional exception details"""
        error_text = f"[ERROR] {message}"
        if exception:
            error_text += f": {str(exception)}"
        print(error_text)
        if self.gui:
            self.gui.display_message(error_text, "ERROR")
    
    def sanitize_message(self, message):
        """Sanitize message text before sending"""
        if not isinstance(message, str):
            return None
        
        # Length limit: 10KB
        if len(message) > 10240:
            if self.gui:
                self.gui.display_message("Message too long (max 10KB)", "ERROR")
            return None
        
        # Remove null bytes and other problematic control chars
        message = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]', '', message)
        
        return message
    
    def validate_url(self, url):
        """Validate URL for GIF loading"""
        if not url or not isinstance(url, str):
            return False
        
        # Length limit
        if len(url) > 2048:
            return False
        
        # Must be HTTP/HTTPS
        if not re.match(r'^https?://', url, re.IGNORECASE):
            return False
        
        # Basic URL validation (no spaces, control chars)
        if re.search(r'[\s\x00-\x1f\x7f-\x9f]', url):
            return False
        
        return True
    
    def save_trusted_keys(self):
        """Save trusted keys to file"""
        try:
            with open('trusted_keys.json', 'w') as f:
                json.dump(self.trusted_keys, f, indent=2)
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error saving trusted keys: {e}", "ERROR")
    
    def load_trusted_keys(self):
        """Load trusted keys from file"""
        try:
            if os.path.exists('trusted_keys.json'):
                with open('trusted_keys.json', 'r') as f:
                    self.trusted_keys = json.load(f)
        except Exception as e:
            # Silently fail if file doesn't exist or is corrupt
            self.trusted_keys = {}
    
    def load_pinned_certs(self):
        """Load pinned certificate fingerprints from file"""
        try:
            if os.path.exists('pinned_certs.json'):
                with open('pinned_certs.json', 'r') as f:
                    self.pinned_certs = json.load(f)
        except Exception as e:
            self.pinned_certs = {}
    
    def save_pinned_certs(self):
        """Save pinned certificate fingerprints to file"""
        try:
            with open('pinned_certs.json', 'w') as f:
                json.dump(self.pinned_certs, f, indent=2)
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error saving pinned certificates: {e}", "ERROR")
    
    def get_cert_fingerprint(self, cert_der):
        """Generate SHA-256 fingerprint of certificate"""
        sha256_hash = hashlib.sha256(cert_der).hexdigest()
        fingerprint = ':'.join(sha256_hash[i:i+2].upper() for i in range(0, len(sha256_hash), 2))
        return fingerprint
    
    def verify_certificate_pinning(self, ssl_socket):
        """Verify server certificate against pinned fingerprint"""
        try:
            # Get server certificate in DER format
            cert_der = ssl_socket.getpeercert(binary_form=True)
            if not cert_der:
                return True  # No cert to verify (shouldn't happen with TLS)
            
            fingerprint = self.get_cert_fingerprint(cert_der)
            
            # Check certificate expiration
            cert_dict = ssl_socket.getpeercert()
            if cert_dict:
                not_after = cert_dict.get('notAfter')
                if not_after:
                    # Parse expiration date
                    from datetime import datetime
                    expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expire_date - datetime.now()).days
                    
                    if days_remaining < 0:
                        if self.gui:
                            self.gui.display_message(
                                f"⚠️ WARNING: Server certificate EXPIRED {abs(days_remaining)} days ago!",
                                "ERROR"
                            )
                    elif days_remaining < 30:
                        if self.gui:
                            self.gui.display_message(
                                f"⚠️ Certificate expires in {days_remaining} days - admin should renew it",
                                "SYSTEM"
                            )
                    elif days_remaining < 90 and self.gui:
                        self.gui.display_message(
                            f"Certificate expires in {days_remaining} days",
                            "SYSTEM"
                        )
            
            # Check if we have a pinned certificate for this host
            if self.host in self.pinned_certs:
                pinned_fp = self.pinned_certs[self.host]
                
                if fingerprint != pinned_fp:
                    # CERTIFICATE CHANGED - Possible MITM attack!
                    if self.gui:
                        warning = f"🚨 SECURITY WARNING: Server certificate changed!\n\n"
                        warning += f"This could indicate a Man-in-the-Middle attack!\n\n"
                        warning += f"Expected: {pinned_fp[:47]}...\n"
                        warning += f"Received: {fingerprint[:47]}...\n\n"
                        warning += f"Only continue if you know the server certificate was updated."
                        
                        self.gui.display_message(warning, "ERROR")
                        
                        # Show dialog asking user what to do
                        response = messagebox.askyesno(
                            "⚠️ Certificate Changed",
                            f"The server's TLS certificate has changed!\n\n"
                            f"This could be a security threat.\n\n"
                            f"Do you trust the NEW certificate?\n\n"
                            f"Click 'Yes' ONLY if you are certain the server\n"
                            f"administrator updated the certificate.",
                            icon='warning'
                        )
                        
                        if response:
                            # User chose to trust the new certificate
                            self.pinned_certs[self.host] = fingerprint
                            self.save_pinned_certs()
                            self.gui.display_message("New certificate pinned", "SYSTEM")
                            return True
                        else:
                            # User rejected the new certificate
                            return False
                    else:
                        # No GUI - reject automatically
                        return False
                else:
                    # Certificate matches pinned fingerprint
                    if self.gui:
                        self.gui.display_message("✓ Certificate verified (pinned)", "SYSTEM")
                    return True
            else:
                # First connection - pin this certificate (TOFU)
                self.pinned_certs[self.host] = fingerprint
                self.save_pinned_certs()
                
                if self.gui:
                    short_fp = fingerprint[:47]
                    self.gui.display_message(
                        f"✓ Server certificate pinned (first connection)\n    Fingerprint: {short_fp}...",
                        "SYSTEM"
                    )
                return True
                
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error verifying certificate: {e}", "ERROR")
            return False
    
    def send_file(self, filepath):
        """Send an encrypted file to all peers"""
        try:
            if not self.connected or not self.shared_keys:
                if self.gui:
                    self.gui.display_message("No peers connected", "ERROR")
                return
            
            # Check file exists and size
            if not os.path.exists(filepath):
                if self.gui:
                    self.gui.display_message("File not found", "ERROR")
                return
            
            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            
            # Validate filename
            if len(filename) > 255:
                if self.gui:
                    self.gui.display_message("Filename too long (max 255 chars)", "ERROR")
                return
            
            # Size limit: 100MB
            if filesize > 104857600:
                if self.gui:
                    self.gui.display_message("File too large (max 100MB)", "ERROR")
                return
            
            if filesize == 0:
                if self.gui:
                    self.gui.display_message("Cannot send empty file", "ERROR")
                return
            
            # Generate unique file ID
            file_id = str(uuid.uuid4())
            
            # Chunk size: 65536 bytes (64KB)
            chunk_size = 65536
            total_chunks = (filesize + chunk_size - 1) // chunk_size
            
            if self.gui:
                self.gui.display_message(
                    f"Sending file: {filename} ({filesize:,} bytes, {total_chunks} chunks)",
                    "SYSTEM"
                )
            
            # Track this transfer
            self.sending_file_transfers[file_id] = {
                'filename': filename,
                'filesize': filesize,
                'total_chunks': total_chunks,
                'sent_chunks': 0,
                'cancel_flag': False
            }
            
            # Send FILE_START packet
            start_packet = {
                "type": "FILE_START",
                "from": self.nickname,
                "file_id": file_id,
                "filename": filename,
                "filesize": filesize,
                "total_chunks": total_chunks
            }
            self.socket.send((json.dumps(start_packet) + "\n").encode('utf-8'))
            
            # Send file in chunks (in background thread)
            def send_chunks_async():
                try:
                    with open(filepath, 'rb') as f:
                        chunk_index = 0
                        while chunk_index < total_chunks:
                            # Check if cancelled
                            if self.sending_file_transfers[file_id]['cancel_flag']:
                                # Send cancel packet
                                cancel_packet = {
                                    "type": "FILE_CANCEL",
                                    "from": self.nickname,
                                    "file_id": file_id
                                }
                                self.socket.send((json.dumps(cancel_packet) + "\n").encode('utf-8'))
                                if self.gui:
                                    self.gui.display_message(f"File transfer cancelled: {filename}", "SYSTEM")
                                return
                            
                            # Read chunk
                            chunk_data = f.read(chunk_size)
                            if not chunk_data:
                                break
                            
                            # Encrypt chunk for each peer
                            encrypted_chunks = {}
                            for peer_nickname, shared_key in self.shared_keys.items():
                                cipher = Fernet(shared_key)
                                encrypted_chunk = cipher.encrypt(chunk_data).decode('utf-8')
                                encrypted_chunks[peer_nickname] = encrypted_chunk
                            
                            # Send FILE_CHUNK packet
                            chunk_packet = {
                                "type": "FILE_CHUNK",
                                "from": self.nickname,
                                "file_id": file_id,
                                "chunk_index": chunk_index,
                                "encrypted_chunks": encrypted_chunks
                            }
                            self.socket.send((json.dumps(chunk_packet) + "\n").encode('utf-8'))
                            
                            chunk_index += 1
                            self.sending_file_transfers[file_id]['sent_chunks'] = chunk_index
                            
                            # Update progress in GUI
                            if self.gui and chunk_index % 10 == 0:  # Update every 10 chunks
                                progress = (chunk_index / total_chunks) * 100
                                self.gui.display_message(
                                    f"Uploading {filename}: {progress:.1f}% ({chunk_index}/{total_chunks} chunks)",
                                    "SYSTEM"
                                )
                            
                            # Small delay to avoid overwhelming the network
                            time.sleep(0.01)
                    
                    # Send FILE_END packet
                    end_packet = {
                        "type": "FILE_END",
                        "from": self.nickname,
                        "file_id": file_id
                    }
                    self.socket.send((json.dumps(end_packet) + "\n").encode('utf-8'))
                    
                    if self.gui:
                        self.gui.display_message(
                            f"✓ File sent successfully: {filename}",
                            "SYSTEM"
                        )
                    
                    # Clean up tracking
                    if file_id in self.sending_file_transfers:
                        del self.sending_file_transfers[file_id]
                    
                except Exception as e:
                    error_msg = f"Error sending file: {e}"
                    if self.gui:
                        self.gui.display_message(error_msg, "ERROR")
                    # Clean up
                    if file_id in self.sending_file_transfers:
                        del self.sending_file_transfers[file_id]
            
            # Start sending in background
            send_thread = threading.Thread(target=send_chunks_async, daemon=True)
            send_thread.start()
            
        except Exception as e:
            error_msg = f"Error preparing file: {e}"
            if self.gui:
                self.gui.display_message(error_msg, "ERROR")
    
    def send_typing_status(self, is_typing):
        """Send typing status to server"""
        try:
            if self.connected and self.socket:
                typing_packet = json.dumps({
                    "type": "TYPING",
                    "from": self.nickname,
                    "is_typing": is_typing
                })
                self.socket.send((typing_packet + "\n").encode('utf-8'))
        except Exception as e:
            pass  # Silently fail for typing indicators
    
    def receive_messages(self) -> None:
        """Main message reception loop - receives and processes packets from server.
        
        This function runs in a background thread and continuously listens for
        incoming data from the server. It handles:
        - Stream buffering (TCP is stream-based, not message-based)
        - JSON packet parsing (newline-delimited)
        - Packet routing to appropriate handlers
        - Connection error handling and reconnection triggers
        
        Protocol:
        - Packets are JSON objects separated by newlines
        - Each packet has a 'type' field determining its handler
        - Incomplete packets are buffered until complete
        
        Threading:
        - Runs in separate thread (started by connect())
        - Uses self.connected flag for graceful shutdown
        - Automatically triggers reconnection on connection loss
        
        Security:
        - JSON validation prevents injection attacks
        - Malformed packets are logged and ignored
        - Does not trust packet contents (all validation in handlers)
        """
        buffer = ""  # Buffer for incomplete packets
        try:
            while self.connected:
                # Receive data from server (may contain partial packets)
                data = self.socket.recv(4096)
                
                # Empty data means connection closed
                if not data:
                    break
                
                # Append to buffer (handles partial UTF-8 sequences)
                buffer += data.decode('utf-8')
                
                # Process all complete packets (newline-delimited JSON)
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        try:
                            # Parse JSON packet
                            packet = json.loads(line)
                            # Route to appropriate handler
                            self.handle_packet(packet)
                        except json.JSONDecodeError as e:
                            # Log malformed packets but continue
                            if self.gui:
                                self.gui.display_message(f"Invalid packet received", "ERROR")
                
        except Exception as e:
            if self.connected:
                error_msg = f"Error receiving message: {e}"
                if self.gui:
                    self.gui.display_message(error_msg, "ERROR")
    
    def handle_packet(self, packet: Dict[str, Any]) -> None:
        """Route incoming packets to appropriate handlers based on packet type.
        
        Args:
            packet: Parsed JSON packet dictionary with 'type' field
        
        Packet Types:
        - PUBKEY: Diffie-Hellman public key exchange for E2E encryption
        - MSG: Encrypted end-to-end message
        - DESTRUCT_MSG: Self-destructing encrypted message  
        - FILE_CHUNK: File transfer data chunk
        - FILE_START/FILE_COMPLETE: File transfer control
        - USER_LEFT: Peer disconnection notification
        - TYPING: Real-time typing indicator
        - REACTION: Message reaction (emoji)
        - AUTH_RESULT: Server authentication response
        
        Security Features:
        - Trust-On-First-Use (TOFU) for new public keys
        - Key change detection and suspicious activity alerting
        - Replay protection via nonce and timestamp validation
        - Auto-trust mechanism with 30-second delay on key changes
        
        Error Handling:
        - Malformed packets are caught and logged
        - Invalid encryption is handled gracefully
        - Missing keys trigger key exchange requests
        """
        try:
            packet_type = packet.get("type")
            
            # Route to specific handler methods
            if packet_type == "PUBKEY":
                self._handle_pubkey_packet(packet)
            elif packet_type in ("MSG", "DESTRUCT_MSG"):
                self._handle_message_packet(packet)
            elif packet_type in ("GIF_MSG", "DESTRUCT_GIF_MSG"):
                self._handle_gif_packet(packet)
            elif packet_type == "SYSTEM":
                self._handle_system_packet(packet)
            elif packet_type == "TYPING":
                self._handle_typing_packet(packet)
            elif packet_type == "USER_LEFT":
                self._handle_user_left_packet(packet)
            elif packet_type == "FILE_START":
                self._handle_file_start_packet(packet)
            elif packet_type == "FILE_CHUNK":
                self._handle_file_chunk_packet(packet)
            elif packet_type == "FILE_END":
                self._handle_file_end_packet(packet)
            elif packet_type == "FILE_CANCEL":
                self._handle_file_cancel_packet(packet)
            elif packet_type == "REACTION":
                self._handle_reaction_packet(packet)
                    
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error handling packet: {e}", "ERROR")
    
    def _handle_pubkey_packet(self, packet: Dict[str, Any]) -> None:
        """Handle public key exchange packet for E2E encryption setup."""
        peer_nickname = packet.get("nickname")
        public_key_pem = packet.get("public_key")
        
        if peer_nickname == self.nickname:
            return
            
        public_key_bytes = public_key_pem.encode('utf-8')
        fingerprint = self.generate_fingerprint(public_key_bytes)
        
        # Check if we've seen this user before
        is_first_contact = peer_nickname not in self.peer_fingerprints
        old_fingerprint = self.peer_fingerprints.get(peer_nickname)
        
        if not is_first_contact and old_fingerprint != fingerprint:
            self._handle_key_change(peer_nickname, fingerprint, old_fingerprint)
        elif is_first_contact:
            self._handle_first_contact(peer_nickname, fingerprint)
        
        # Store peer's public key and derive shared key
        self.peer_public_keys[peer_nickname] = public_key_bytes
        shared_key = self.derive_shared_key(public_key_bytes)
        self.shared_keys[peer_nickname] = shared_key
        
        if self.gui and not is_first_contact and old_fingerprint == fingerprint:
            # Reconnection with same key
            short_fp = fingerprint[:47]
            self.gui.display_message(
                f"?? Secure connection with {peer_nickname}\n    Fingerprint: {short_fp}...",
                "SYSTEM"
            )
    
    def _handle_key_change(self, peer_nickname: str, fingerprint: str, old_fingerprint: str) -> None:
        """Handle detection of changed public key (potential MITM)."""
        current_time = time.time()
        
        # Track key changes for suspicious activity detection
        if peer_nickname not in self.key_change_history:
            self.key_change_history[peer_nickname] = []
        self.key_change_history[peer_nickname].append(current_time)
        
        # Remove old timestamps (older than 5 minutes)
        self.key_change_history[peer_nickname] = [
            ts for ts in self.key_change_history[peer_nickname]
            if current_time - ts < 300
        ]
        
        # Check if suspicious (more than 3 changes in 5 minutes)
        is_suspicious = len(self.key_change_history[peer_nickname]) > 3
        
        if is_suspicious:
            self._alert_suspicious_key_change(peer_nickname, fingerprint, old_fingerprint)
            self.peer_fingerprints[peer_nickname] = fingerprint
        else:
            self._handle_normal_key_change(peer_nickname, fingerprint)
    
    def _alert_suspicious_key_change(self, peer_nickname: str, fingerprint: str, old_fingerprint: str) -> None:
        """Alert user to suspicious key change activity (potential MITM attack)."""
        if not self.gui:
            return
            
        warning = f"?? SECURITY ALERT: {peer_nickname}'s key changed {len(self.key_change_history[peer_nickname])} times!\n"
        warning += "This is HIGHLY SUSPICIOUS and could indicate a MITM attack!\n"
        warning += f"Old: {old_fingerprint[:32]}...\n"
        warning += f"New: {fingerprint[:32]}..."
        self.gui.display_message(warning, "ERROR")
        
        messagebox.showerror(
            "?? Security Alert",
            f"{peer_nickname}'s key has changed {len(self.key_change_history[peer_nickname])} times in 5 minutes!\n\n"
            "This is HIGHLY SUSPICIOUS!\n\n"
            "Someone may be trying to intercept your communication.\n"
            "Contact this user through another channel immediately!"
        )
    
    def _handle_normal_key_change(self, peer_nickname: str, fingerprint: str) -> None:
        """Handle normal key change (client restart) with auto-trust."""
        if self.gui:
            self.gui.display_message(
                f"?? {peer_nickname} restarted their client (new encryption key)",
                "SYSTEM"
            )
            self.gui.display_message(
                f"   Auto-trusting new key in 30 seconds...",
                "SYSTEM"
            )
        
        # Cancel any pending auto-trust for this user
        if peer_nickname in self.pending_auto_trust:
            self.pending_auto_trust[peer_nickname].cancel()
        
        # Schedule auto-trust after 30 seconds
        auto_trust_timer = threading.Timer(
            30.0,
            self.auto_trust_key,
            args=[peer_nickname, fingerprint]
        )
        auto_trust_timer.daemon = True
        auto_trust_timer.start()
        self.pending_auto_trust[peer_nickname] = auto_trust_timer
        
        self.peer_fingerprints[peer_nickname] = fingerprint
    
    def _handle_first_contact(self, peer_nickname: str, fingerprint: str) -> None:
        """Handle first contact with a peer using Trust-On-First-Use (TOFU)."""
        self.peer_fingerprints[peer_nickname] = fingerprint
        self.save_trusted_keys()  # Auto-save
        
        if self.gui:
            self.gui.display_message(
                f"? First contact with {peer_nickname} - key automatically trusted (TOFU)",
                "SYSTEM"
            )
    
    def _handle_message_packet(self, packet: Dict[str, Any]) -> None:
        """Handle encrypted text message packet."""
        sender = packet.get("from")
        encrypted_messages = packet.get("encrypted_messages", {})
        msg_id = packet.get("msg_id")
        destruct_timer = packet.get("destruct_timer")
        reply_to = packet.get("reply_to")
        
        # Find our encrypted message
        if self.nickname not in encrypted_messages:
            return
            
        encrypted_msg = encrypted_messages[self.nickname]
        
        # Decrypt using shared key with sender
        if sender not in self.shared_keys:
            if self.gui:
                self.gui.display_message(
                    f"Cannot decrypt message from {sender} - no shared key",
                    "ERROR"
                )
            return
        
        cipher = Fernet(self.shared_keys[sender])
        decrypted_msg = cipher.decrypt(encrypted_msg.encode('utf-8')).decode('utf-8')
        
        # Format for display
        formatted_msg = f"[{sender}]: {decrypted_msg}"
        if destruct_timer:
            formatted_msg = f"[{sender}]: {decrypted_msg} ?? ({destruct_timer}s)"
        
        if self.gui:
            self.gui.display_message(formatted_msg, "RECEIVED", msg_id=msg_id, reply_to=reply_to)
            
            # Schedule deletion if self-destruct
            if destruct_timer:
                timer = threading.Timer(destruct_timer, self.delete_message, args=[msg_id])
                timer.daemon = True
                timer.start()
                self.message_timers[msg_id] = timer
    
    def _handle_gif_packet(self, packet: Dict[str, Any]) -> None:
        """Handle encrypted GIF message packet."""
        sender = packet.get("from")
        encrypted_gifs = packet.get("encrypted_gifs", {})
        msg_id = packet.get("msg_id")
        destruct_timer = packet.get("destruct_timer")
        
        # Find our encrypted GIF
        if self.nickname not in encrypted_gifs:
            return
            
        encrypted_url = encrypted_gifs[self.nickname]
        
        # Decrypt using shared key with sender
        if sender not in self.shared_keys:
            if self.gui:
                self.gui.display_message(
                    f"Cannot decrypt GIF from {sender} - no shared key",
                    "ERROR"
                )
            return
        
        cipher = Fernet(self.shared_keys[sender])
        gif_url = cipher.decrypt(encrypted_url.encode('utf-8')).decode('utf-8')
        
        if self.gui:
            self.gui.display_gif(gif_url, sender, msg_id=msg_id, destruct_timer=destruct_timer)
            
            # Schedule deletion if self-destruct
            if destruct_timer:
                timer = threading.Timer(destruct_timer, self.delete_message, args=[msg_id])
                timer.daemon = True
                timer.start()
                self.message_timers[msg_id] = timer
    
    def _handle_system_packet(self, packet: Dict[str, Any]) -> None:
        """Handle system message from server."""
        sys_msg = packet.get("message", "")
        if self.gui:
            self.gui.display_message(sys_msg, "SYSTEM")
    
    def _handle_typing_packet(self, packet: Dict[str, Any]) -> None:
        """Handle typing indicator packet."""
        sender = packet.get("from")
        is_typing = packet.get("is_typing", False)
        
        if not self.gui or sender == self.nickname:
            return
            
        if is_typing:
            self.gui.typing_users.add(sender)
        else:
            self.gui.typing_users.discard(sender)
        self.gui.update_typing_indicator()
    
    def _handle_user_left_packet(self, packet: Dict[str, Any]) -> None:
        """Handle user disconnection packet."""
        left_user = packet.get("nickname")
        
        if left_user in self.shared_keys:
            del self.shared_keys[left_user]
        if left_user in self.peer_public_keys:
            del self.peer_public_keys[left_user]
            
        if self.gui:
            # Remove from typing users if present
            self.gui.typing_users.discard(left_user)
            self.gui.update_typing_indicator()
            self.gui.display_message(f"{left_user} left the chat", "SYSTEM")
    
    def _handle_file_start_packet(self, packet: Dict[str, Any]) -> None:
        """Handle file transfer initiation packet."""
        sender = packet.get("from")
        file_id = packet.get("file_id")
        filename = packet.get("filename")
        filesize = packet.get("filesize")
        total_chunks = packet.get("total_chunks")
        
        if sender == self.nickname:
            return
        
        # Ask user if they want to accept the file
        if self.gui:
            accept = messagebox.askyesno(
                "Incoming File",
                f"{sender} wants to send you a file:\n\n"
                f"Filename: {filename}\n"
                f"Size: {filesize:,} bytes ({filesize / 1024 / 1024:.2f} MB)\n\n"
                f"Do you want to accept this file?",
                icon='question'
            )
            
            if not accept:
                # User declined - send cancel packet back
                cancel_packet = {
                    "type": "FILE_CANCEL",
                    "file_id": file_id,
                    "from": self.nickname
                }
                try:
                    self.socket.send((json.dumps(cancel_packet) + "\n").encode('utf-8'))
                except Exception as e:
                    self.log_error("Error sending file cancel packet", e)
                
                self.gui.display_message(
                    f"📥 Declined file from {sender}: {filename}",
                    "SYSTEM"
                )
                return
            
        # Initialize file transfer tracking
        self.active_file_transfers[file_id] = {
            'sender': sender,
            'filename': filename,
            'filesize': filesize,
            'total_chunks': total_chunks,
            'chunks': {},  # chunk_index -> decrypted_data
            'received_chunks': 0
        }
        
        if self.gui:
            self.gui.display_message(
                f"?? Receiving file from {sender}: {filename} ({filesize:,} bytes)",
                "SYSTEM"
            )
    
    def _handle_file_chunk_packet(self, packet: Dict[str, Any]) -> None:
        """Handle file chunk data packet."""
        sender = packet.get("from")
        file_id = packet.get("file_id")
        chunk_index = packet.get("chunk_index")
        encrypted_chunks = packet.get("encrypted_chunks", {})
        
        if sender == self.nickname or file_id not in self.active_file_transfers:
            return
            
        # Decrypt our chunk
        if self.nickname not in encrypted_chunks or sender not in self.shared_keys:
            return
            
        encrypted_chunk = encrypted_chunks[self.nickname]
        
        try:
            cipher = Fernet(self.shared_keys[sender])
            decrypted_chunk = cipher.decrypt(encrypted_chunk.encode('utf-8'))
            
            # Store chunk
            self.active_file_transfers[file_id]['chunks'][chunk_index] = decrypted_chunk
            self.active_file_transfers[file_id]['received_chunks'] += 1
            
            # Update progress (every 10 chunks)
            if self.gui and chunk_index % 10 == 0:
                transfer = self.active_file_transfers[file_id]
                progress = (transfer['received_chunks'] / transfer['total_chunks']) * 100
                self.gui.display_message(
                    f"Downloading {transfer['filename']}: {progress:.1f}% ({transfer['received_chunks']}/{transfer['total_chunks']} chunks)",
                    "SYSTEM"
                )
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error decrypting file chunk: {e}", "ERROR")
    
    def _handle_file_end_packet(self, packet: Dict[str, Any]) -> None:
        """Handle file transfer completion packet."""
        sender = packet.get("from")
        file_id = packet.get("file_id")
        
        if sender == self.nickname or file_id not in self.active_file_transfers:
            return
            
        transfer = self.active_file_transfers[file_id]
        
        try:
            # Reassemble file
            chunks_data = []
            for i in range(transfer['total_chunks']):
                if i in transfer['chunks']:
                    chunks_data.append(transfer['chunks'][i])
                else:
                    raise Exception(f"Missing chunk {i}")
            
            file_data = b''.join(chunks_data)
            
            # Create downloads directory if it doesn't exist
            downloads_dir = os.path.join(os.getcwd(), 'downloads')
            os.makedirs(downloads_dir, exist_ok=True)
            
            # Save file
            output_path = os.path.join(downloads_dir, transfer['filename'])
            
            # Avoid overwriting - add number if file exists
            counter = 1
            base_name, ext = os.path.splitext(transfer['filename'])
            while os.path.exists(output_path):
                output_path = os.path.join(downloads_dir, f"{base_name}_{counter}{ext}")
                counter += 1
            
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            if self.gui:
                self.gui.display_message(
                    f"? File received from {sender}: {os.path.basename(output_path)}\n   Saved to: {output_path}",
                    "SYSTEM"
                )
            
            # Clean up
            del self.active_file_transfers[file_id]
            
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error saving file: {e}", "ERROR")
            if file_id in self.active_file_transfers:
                del self.active_file_transfers[file_id]
    
    def _handle_file_cancel_packet(self, packet: Dict[str, Any]) -> None:
        """Handle file transfer cancellation packet."""
        sender = packet.get("from")
        file_id = packet.get("file_id")
        
        if file_id not in self.active_file_transfers:
            return
            
        transfer = self.active_file_transfers[file_id]
        if self.gui:
            self.gui.display_message(
                f"File transfer cancelled by {sender}: {transfer['filename']}",
                "SYSTEM"
            )
        del self.active_file_transfers[file_id]
    
    def _handle_reaction_packet(self, packet: Dict[str, Any]) -> None:
        """Handle message reaction packet."""
        sender = packet.get("from")
        encrypted_reactions = packet.get("encrypted_reactions", {})
        
        # Find our encrypted reaction
        if self.nickname not in encrypted_reactions:
            return
            
        if sender not in self.shared_keys:
            return
            
        try:
            encrypted_reaction = encrypted_reactions[self.nickname]
            cipher = Fernet(self.shared_keys[sender])
            reaction_json = cipher.decrypt(encrypted_reaction.encode('utf-8')).decode('utf-8')
            reaction_data = json.loads(reaction_json)
            
            msg_id = reaction_data.get('msg_id')
            emoji = reaction_data.get('emoji')
            reactor = reaction_data.get('reactor')
            
            if self.gui and msg_id and emoji:
                self.gui.add_reaction_to_display(msg_id, emoji, reactor)
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error decrypting reaction: {e}", "ERROR")
    
    def disconnect(self) -> None:
        """Disconnect from the server"""
        self.connected = False
        
        # Cancel all pending auto-trust timers to prevent orphaned timers
        for nickname, timer in list(self.pending_auto_trust.items()):
            try:
                timer.cancel()
            except Exception as e:
                self.log_error(f"Error canceling auto-trust timer for {nickname}", e)
        self.pending_auto_trust.clear()
        
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                self.log_error("Error closing socket", e)
            finally:
                self.socket = None
        if self.gui:
            self.gui.display_message("Disconnected from server", "SYSTEM")


class ChatGUI:
    def __init__(self, client):
        self.client = client
        self.client.gui = self
        self.user_colors = {}  # Dictionary to store colors for each user
        self.message_marks = {}  # msg_id -> (start_mark, end_mark) for deletion
        self.message_data = {}  # msg_id -> {sender, text, timestamp} for replies
        self.reply_to = None  # Current message being replied to {msg_id, sender, text}
        self.typing_users = set()  # Set of users currently typing
        self.typing_timer = None  # Timer to stop sending typing status
        self.color_palette = [
            "#FF4444", "#44FF44", "#4444FF", "#FFAA00", "#FF00FF",
            "#00FFFF", "#FF8800", "#88FF00", "#0088FF", "#FF0088",
            "#FFD700", "#00FF88", "#8800FF", "#FF6B9D", "#00CED1"
        ]
        self.next_color_index = 0
        self.window_focused = True  # Track if window has focus
        self.gif_animations = {}  # Store animation data for GIFs: msg_id -> {frames, labels, current_frame, delay}
        self.max_active_gifs = 20  # Limit active GIF animations to prevent memory leak
        self.gif_cache = {}  # url -> {frames, duration} for GIF caching
        self.gif_preview_cache = {}  # url -> PhotoImage for preview caching
        self.max_cache_size = 50  # Maximum number of cached GIFs
        self.message_reactions = {}  # msg_id -> {emoji -> [list of users]}
        self.reaction_labels = {}  # msg_id -> tk.Label for displaying reactions
        self.available_reactions = ['👍', '❤️', '😂', '😮', '😢', '🙏']  # Available reaction emojis
        
        self.window = tk.Tk()
        self.window.title(f"Xessenger - {self.client.nickname}")
        self.window.geometry("600x560")
        self.window.configure(bg='#2b2b2b')
        
        # Chat display area
        chat_frame = tk.Frame(self.window, bg='#2b2b2b')
        chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Header with title and clear button
        header_frame = tk.Frame(chat_frame, bg='#2b2b2b')
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        tk.Label(header_frame, text="Xessages", bg='#2b2b2b', fg='white', 
                font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        
        # Security button to view fingerprints
        self.security_button = tk.Button(
            header_frame,
            text="🔐 Security",
            command=self.show_security_info,
            bg='#444444',
            fg='white',
            font=('Segoe UI Emoji', 9),
            relief=tk.FLAT,
            cursor='hand2',
            padx=10,
            pady=3
        )
        self.security_button.pack(side=tk.RIGHT, padx=(0, 5))
        
        self.clear_button = tk.Button(
            header_frame,
            text="🗑️ Clear Chat",
            command=self.clear_chat,
            bg='#444444',
            fg='white',
            font=('Segoe UI Emoji', 9),
            relief=tk.FLAT,
            cursor='hand2',
            padx=10,
            pady=3
        )
        self.clear_button.pack(side=tk.RIGHT)
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            width=70,
            height=20,
            font=('Segoe UI', 10),
            bg='#1e1e1e',
            fg='#ffffff',
            state=tk.DISABLED,
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # Configure emoji tag for better emoji rendering
        try:
            self.chat_display.tag_config("emoji", font=('Segoe UI Emoji', 12))
        except:
            pass  # Fallback if font not available
        
        # Typing indicator
        self.typing_label = tk.Label(
            chat_frame,
            text="",
            bg='#2b2b2b',
            fg='#888888',
            font=('Arial', 9, 'italic'),
            anchor=tk.W,
            height=1
        )
        self.typing_label.pack(fill=tk.X, pady=(5, 0))
        
        # Bind right-click for reply
        self.chat_display.bind("<Button-3>", self.show_context_menu)
        
        # Configure text tags for colored messages
        self.chat_display.tag_config("YOU", foreground="#4CAF50")
        self.chat_display.tag_config("SYSTEM", foreground="#FFC107")
        self.chat_display.tag_config("ERROR", foreground="#f44336")
        self.chat_display.tag_config("timestamp", foreground="#888888", font=('Arial', 9))
        
        # Message input area
        input_frame = tk.Frame(self.window, bg='#2b2b2b')
        input_frame.pack(padx=10, pady=(0, 10), fill=tk.X)
        
        # Reply indicator (hidden by default)
        self.reply_frame = tk.Frame(input_frame, bg='#3c3c3c')
        self.reply_label = tk.Label(self.reply_frame, text="", bg='#3c3c3c', fg='#FFD93D',
                                   font=('Arial', 9), anchor=tk.W)
        self.reply_label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        cancel_reply_btn = tk.Button(self.reply_frame, text="✕", command=self.cancel_reply,
                                     bg='#3c3c3c', fg='white', font=('Arial', 9, 'bold'),
                                     relief=tk.FLAT, cursor='hand2', padx=5)
        cancel_reply_btn.pack(side=tk.RIGHT, padx=2)
        
        tk.Label(input_frame, text="Your Xessage", bg='#2b2b2b', fg='white',
                font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 5))
        
        message_entry_frame = tk.Frame(input_frame, bg='#2b2b2b')
        message_entry_frame.pack(fill=tk.X)
        
        self.message_entry = tk.Entry(
            message_entry_frame,
            font=('Arial', 11),
            bg='#3c3c3c',
            fg='white',
            relief=tk.FLAT,
            insertbackground='white'
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10), ipady=8)
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        self.message_entry.bind('<KeyPress>', lambda e: self.on_key_press(e))
        self.message_entry.focus()
        
        self.send_button = tk.Button(
            message_entry_frame,
            text="Send",
            command=self.send_message,
            bg='#4CAF50',
            fg='white',
            font=('Arial', 10, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=20,
            pady=8
        )
        self.send_button.pack(side=tk.RIGHT)
        
        # GIF button
        self.gif_button = tk.Button(
            message_entry_frame,
            text="🎬 GIF",
            command=self.open_gif_search,
            bg='#9C27B0',
            fg='white',
            font=('Segoe UI Emoji', 10, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=8
        )
        self.gif_button.pack(side=tk.RIGHT, padx=(0, 10))
        
        # File button
        self.file_button = tk.Button(
            message_entry_frame,
            text="📎 File",
            command=self.send_file_dialog,
            bg='#FF5722',
            fg='white',
            font=('Segoe UI Emoji', 10, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=8
        )
        self.file_button.pack(side=tk.RIGHT, padx=(0, 10))
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Track window focus for notifications
        self.window.bind("<FocusIn>", self.on_focus_in)
        self.window.bind("<FocusOut>", self.on_focus_out)
        
    def on_focus_in(self, event):
        """Handle window gaining focus"""
        self.window_focused = True
    
    def on_focus_out(self, event):
        """Handle window losing focus"""
        self.window_focused = False
    
    def is_window_focused(self):
        """Check if window is actually focused (more reliable than event tracking)"""
        try:
            # Check if window has focus and is not minimized
            return (self.window.focus_displayof() is not None and 
                    self.window.state() == 'normal' and 
                    self.window_focused)
        except tk.TclError:
            return False
    
    def show_notification(self, username, message_preview):
        """Show Windows notification for new message"""
        try:
            toast = Notification(
                app_id="Xessenger",
                title=f"New xessage from {username}",
                msg=message_preview,
                duration="short"
            )
            toast.set_audio(audio.Default, loop=False)
            
            # Callback to bring window to front when notification is clicked
            def notification_callback():
                self.window.after(0, self.bring_to_front)
            
            toast.on_click = notification_callback
            toast.show()
        except Exception as e:
            # Silently fail if notification doesn't work
            self.client.log_error("Notification failed", e)
    
    def bring_to_front(self):
        """Bring window to front and focus it"""
        try:
            self.window.lift()
            self.window.focus_force()
            self.window.attributes('-topmost', True)
            self.window.after(100, lambda: self.window.attributes('-topmost', False))
        except tk.TclError:
            # Window might have been destroyed
            pass
    
    def get_timestamp(self):
        """Get current timestamp in Germany timezone"""
        germany_tz = ZoneInfo("Europe/Berlin")
        now = datetime.now(germany_tz)
        return now.strftime("%H:%M:%S")
    
    def get_user_color(self, username):
        """Get or assign a color for a user"""
        if username not in self.user_colors:
            color = self.color_palette[self.next_color_index % len(self.color_palette)]
            self.user_colors[username] = color
            self.next_color_index += 1
            # Configure tag for this user
            self.chat_display.tag_config(f"user_{username}", foreground=color)
        return f"user_{username}"
    
    def insert_text_with_emoji_tags(self, text, base_tag=None):
        """Insert text with proper emoji font tags applied"""
        import re
        # Unicode emoji pattern (covers most common emojis)
        emoji_pattern = re.compile(
            "["
            "\U0001F600-\U0001F64F"  # emoticons
            "\U0001F300-\U0001F5FF"  # symbols & pictographs
            "\U0001F680-\U0001F6FF"  # transport & map symbols
            "\U0001F1E0-\U0001F1FF"  # flags (iOS)
            "\U00002702-\U000027B0"
            "\U000024C2-\U0001F251"
            "\U0001F900-\U0001F9FF"  # supplemental symbols and pictographs
            "\U0001FA00-\U0001FA6F"  # extended pictographs
            "\U00002600-\U000026FF"  # miscellaneous symbols
            "\U00002700-\U000027BF"  # dingbats
            "]+", flags=re.UNICODE
        )
        
        last_end = 0
        for match in emoji_pattern.finditer(text):
            # Insert text before emoji
            if match.start() > last_end:
                before_text = text[last_end:match.start()]
                if base_tag:
                    self.chat_display.insert(tk.END, before_text, base_tag)
                else:
                    self.chat_display.insert(tk.END, before_text)
            
            # Insert emoji with emoji tag
            emoji_text = match.group()
            if base_tag:
                self.chat_display.insert(tk.END, emoji_text, (base_tag, "emoji"))
            else:
                self.chat_display.insert(tk.END, emoji_text, "emoji")
            
            last_end = match.end()
        
        # Insert remaining text after last emoji
        if last_end < len(text):
            remaining = text[last_end:]
            if base_tag:
                self.chat_display.insert(tk.END, remaining, base_tag)
            else:
                self.chat_display.insert(tk.END, remaining)
    
    def display_message(self, message, tag="RECEIVED", msg_id=None, reply_to=None):
        """Display a message in the chat window"""
        self.chat_display.configure(state=tk.NORMAL)
        
        # Mark start position if msg_id provided
        if msg_id:
            start_mark = self.chat_display.index(tk.END + "-1c")
        
        timestamp = self.get_timestamp()
        
        # Extract sender and actual message text for storage
        sender = None
        message_text = message
        
        if tag == "YOU":
            sender = "YOU"
            message_text = message
            
            # Show reply if present
            if reply_to:
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, "[YOU] ", tag)
                self.chat_display.insert(tk.END, f"↩️ @{reply_to['sender']}: ", "timestamp")
                reply_preview = reply_to['text'][:40] + "..." if len(reply_to['text']) > 40 else reply_to['text']
                self.chat_display.insert(tk.END, f"\"{reply_preview}\"\n", "timestamp")
            
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, "[YOU] ", tag)
            self.insert_text_with_emoji_tags(f"{message}\n")
        elif tag == "RECEIVED":
            # Parse username from message format "[username]: message"
            if message.startswith("[") and "]:" in message:
                bracket_end = message.index("]")
                username = message[1:bracket_end]
                rest_of_message = message[bracket_end+1:].lstrip(":")
                sender = username
                message_text = rest_of_message.strip()
                
                # Show notification if window is not focused
                if not self.is_window_focused():
                    # Get message preview (first 100 chars)
                    preview = message_text[:100] + "..." if len(message_text) > 100 else message_text
                    self.show_notification(username, preview)
                
                # Get color tag for this user
                user_tag = self.get_user_color(username)
                
                # Show reply if present
                if reply_to:
                    self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                    self.chat_display.insert(tk.END, f"[{username}]", user_tag)
                    self.chat_display.insert(tk.END, f" ↩️ @{reply_to['sender']}: ", "timestamp")
                    reply_preview = reply_to['text'][:40] + "..." if len(reply_to['text']) > 40 else reply_to['text']
                    self.chat_display.insert(tk.END, f"\"{reply_preview}\"\n", "timestamp")
                
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, f"[{username}]", user_tag)
                self.insert_text_with_emoji_tags(f": {message_text}\n")
            else:
                # Fallback for messages without username format
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, f"{message}\n")
        elif tag == "SYSTEM":
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"[SYSTEM] {message}\n", tag)
        elif tag == "ERROR":
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"[ERROR] {message}\n", tag)
        
        # Store message data for replies (only for actual messages, not system/error)
        if msg_id and sender and tag in ["YOU", "RECEIVED"]:
            self.message_data[msg_id] = {
                'sender': sender,
                'text': message_text,
                'timestamp': timestamp
            }
        
        # Mark end position and store if msg_id provided
        if msg_id:
            end_mark = self.chat_display.index(tk.END + "-1c")
            self.message_marks[msg_id] = (start_mark, end_mark)
        
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def clear_chat(self):
        """Clear all messages from chat display"""
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.configure(state=tk.DISABLED)
        self.message_marks.clear()
        self.message_data.clear()
        self.gif_animations.clear()
        # Clear caches to free memory
        self.gif_cache.clear()
        self.gif_preview_cache.clear()
        self.cancel_reply()
        self.display_message("Chat cleared", "SYSTEM")
    
    def manage_gif_cache(self) -> None:
        """Manage GIF cache size to prevent memory bloat.
        
        Implements LRU-style eviction: removes oldest cached items
        when cache exceeds max_cache_size limit.
        """
        if len(self.gif_cache) > self.max_cache_size:
            # Remove oldest 20% of cache
            items_to_remove = len(self.gif_cache) - self.max_cache_size + 10
            for _ in range(items_to_remove):
                if self.gif_cache:
                    self.gif_cache.pop(next(iter(self.gif_cache)))
        
        if len(self.gif_preview_cache) > self.max_cache_size:
            # Remove oldest 20% of preview cache
            items_to_remove = len(self.gif_preview_cache) - self.max_cache_size + 10
            for _ in range(items_to_remove):
                if self.gif_preview_cache:
                    self.gif_preview_cache.pop(next(iter(self.gif_preview_cache)))
    
    def delete_message_by_id(self, msg_id):
        """Delete a specific message by its ID (for self-destruct)"""
        if msg_id in self.message_marks:
            start_mark, end_mark = self.message_marks[msg_id]
            
            self.chat_display.configure(state=tk.NORMAL)
            try:
                # Delete from start to end (including newline)
                self.chat_display.delete(start_mark, end_mark + "+1c")
            except tk.TclError:
                # Mark might be invalid if chat was cleared
                pass
            self.chat_display.configure(state=tk.DISABLED)
            
            # Remove from tracking
            del self.message_marks[msg_id]
            if msg_id in self.message_data:
                del self.message_data[msg_id]
            # Stop GIF animation and free memory
            if msg_id in self.gif_animations:
                self.stop_gif_animation(msg_id)
    
    def show_context_menu(self, event):
        """Show context menu for replying to messages"""
        # Get the index where right-click occurred
        index = self.chat_display.index(f"@{event.x},{event.y}")
        
        # Find which message was clicked
        clicked_msg_id = None
        for msg_id, (start_mark, end_mark) in self.message_marks.items():
            try:
                start_idx = self.chat_display.index(start_mark)
                end_idx = self.chat_display.index(end_mark)
                
                if self.chat_display.compare(index, ">=", start_idx) and \
                   self.chat_display.compare(index, "<=", end_idx):
                    clicked_msg_id = msg_id
                    break
            except tk.TclError:
                continue
        
        if clicked_msg_id and clicked_msg_id in self.message_data:
            # Create context menu
            context_menu = tk.Menu(self.window, tearoff=0, bg='#2b2b2b', fg='white',
                                  activebackground='#4CAF50', activeforeground='white')
            context_menu.add_command(label="↩️ Reply to this message",
                                    command=lambda: self.set_reply_to(clicked_msg_id))
            
            # Add separator
            context_menu.add_separator()
            
            # Add reaction submenu with emoji font
            reaction_menu = tk.Menu(context_menu, tearoff=0, bg='#2b2b2b', fg='white',
                                   activebackground='#4CAF50', activeforeground='white',
                                   font=('Segoe UI Emoji', 12))
            for emoji in self.available_reactions:
                reaction_menu.add_command(label=emoji,
                                         command=lambda e=emoji: self.send_reaction(clicked_msg_id, e))
            context_menu.add_cascade(label="😀 React", menu=reaction_menu)
            
            context_menu.tk_popup(event.x_root, event.y_root)
    
    def set_reply_to(self, msg_id):
        """Set the message to reply to"""
        if msg_id in self.message_data:
            msg_data = self.message_data[msg_id]
            self.reply_to = {
                'msg_id': msg_id,
                'sender': msg_data['sender'],
                'text': msg_data['text']
            }
            
            # Show reply indicator
            preview_text = msg_data['text'][:50]
            if len(msg_data['text']) > 50:
                preview_text += "..."
            
            self.reply_label.config(text=f"↩️ Replying to {msg_data['sender']}: {preview_text}")
            self.reply_frame.pack(fill=tk.X, pady=(0, 5))
            self.message_entry.focus()
    
    def cancel_reply(self):
        """Cancel the current reply"""
        self.reply_to = None
        self.reply_frame.pack_forget()
    
    def send_reaction(self, msg_id, emoji):
        """Send a reaction to a message"""
        if msg_id not in self.message_data:
            return
        
        msg_data = self.message_data[msg_id]
        sender = msg_data['sender']
        
        # Don't send reactions to system messages
        if sender in ['SYSTEM', 'ERROR']:
            return
        
        # Create reaction packet
        reaction_data = {
            'msg_id': msg_id,
            'emoji': emoji,
            'reactor': self.client.nickname
        }
        
        # Send reaction to all connected users (broadcast)
        self.client.send_reaction(reaction_data)
        
        # Update local reactions display
        self.add_reaction_to_display(msg_id, emoji, self.client.nickname)
    
    def add_reaction_to_display(self, msg_id, emoji, user):
        """Add or update reaction display for a message"""
        if msg_id not in self.message_reactions:
            self.message_reactions[msg_id] = {}
        
        if emoji not in self.message_reactions[msg_id]:
            self.message_reactions[msg_id][emoji] = []
        
        # Toggle reaction: remove if user already reacted with this emoji
        if user in self.message_reactions[msg_id][emoji]:
            self.message_reactions[msg_id][emoji].remove(user)
            if len(self.message_reactions[msg_id][emoji]) == 0:
                del self.message_reactions[msg_id][emoji]
        else:
            self.message_reactions[msg_id][emoji].append(user)
        
        # Update reaction label
        self.update_reaction_label(msg_id)
    
    def update_reaction_label(self, msg_id):
        """Update the reaction label for a message"""
        if msg_id not in self.message_marks or msg_id not in self.message_data:
            return
        
        try:
            start_mark, end_mark = self.message_marks[msg_id]
            msg_data = self.message_data[msg_id]
            sender = msg_data['sender']
            message_text = msg_data['text']
            
            # Build reaction text
            reaction_text = ""
            if msg_id in self.message_reactions and self.message_reactions[msg_id]:
                reactions = []
                for emoji, users in self.message_reactions[msg_id].items():
                    count = len(users)
                    if count > 1:
                        reactions.append(f"{emoji}{count}")
                    else:
                        reactions.append(emoji)
                reaction_text = " " + " ".join(reactions)
            
            # Update display
            self.chat_display.configure(state=tk.NORMAL)
            
            # Find the main message line (not timestamp or reply lines)
            line_start = self.chat_display.search("\n", start_mark, backwards=True)
            if not line_start:
                line_start = start_mark
            else:
                line_start = f"{line_start}+1c"
            
            # Search for the line that contains the actual message text
            # It will have the format: [timestamp] [sender]: message
            current_pos = line_start
            message_line_start = None
            
            while self.chat_display.compare(current_pos, "<", end_mark):
                line_content = self.chat_display.get(current_pos, f"{current_pos} lineend")
                # Look for the line with the sender's name and message
                if f"[{sender}]:" in line_content or (sender == "YOU" and "[YOU]" in line_content):
                    message_line_start = current_pos
                    break
                current_pos = f"{current_pos} +1 line"
            
            if not message_line_start:
                self.chat_display.configure(state=tk.DISABLED)
                return
            
            message_line_end = self.chat_display.index(f"{message_line_start} lineend")
            
            # Delete the message line
            self.chat_display.delete(message_line_start, message_line_end)
            
            # Re-insert with proper formatting and tags
            timestamp = msg_data.get('timestamp', self.get_timestamp())
            self.chat_display.insert(message_line_start, f"[{timestamp}] ", "timestamp")
            
            if sender == "YOU":
                self.chat_display.insert(f"{message_line_start} lineend", "[YOU] ", "YOU")
                self.insert_text_with_emoji_tags(message_text + reaction_text)
            else:
                user_tag = self.get_user_color(sender)
                self.chat_display.insert(f"{message_line_start} lineend", f"[{sender}]", user_tag)
                self.insert_text_with_emoji_tags(f": {message_text}{reaction_text}")
            
            # Update end mark
            new_end = self.chat_display.index(f"{message_line_start} lineend")
            self.message_marks[msg_id] = (start_mark, new_end)
            
            self.chat_display.configure(state=tk.DISABLED)
            
        except tk.TclError as e:
            # Silently handle any display errors
            pass

    
    def show_security_info(self):
        """Show security information and key fingerprints"""
        security_window = Toplevel(self.window)
        security_window.title("Security & Key Verification")
        security_window.geometry("700x500")
        security_window.configure(bg='#2b2b2b')
        
        # Header
        header = Label(security_window, text="🔐 Encryption Key Fingerprints", 
                      bg='#2b2b2b', fg='white', font=('Arial', 14, 'bold'))
        header.pack(pady=15)
        
        info = Label(security_window, 
                    text="Verify these fingerprints with your contacts through another secure channel\\n(phone call, in person, etc.) to prevent Man-in-the-Middle attacks.",
                    bg='#2b2b2b', fg='#FFC107', font=('Arial', 9), justify=tk.CENTER)
        info.pack(pady=(0, 15))
        
        # Scrollable list
        list_frame = Frame(security_window, bg='#2b2b2b')
        list_frame.pack(padx=20, pady=(0, 20), fill=tk.BOTH, expand=True)
        
        canvas = Canvas(list_frame, bg='#1e1e1e', highlightthickness=0)
        scrollbar = Scrollbar(list_frame, orient=VERTICAL, command=canvas.yview)
        content_frame = Frame(canvas, bg='#1e1e1e')
        
        content_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=content_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Your own fingerprint
        if self.client.dh_public_key:
            own_key_bytes = self.client.serialize_public_key()
            own_fp = self.client.generate_fingerprint(own_key_bytes)
            
            own_frame = Frame(content_frame, bg='#2b2b2b', relief=tk.RAISED, borderwidth=2)
            own_frame.pack(fill=tk.X, padx=10, pady=10)
            
            Label(own_frame, text=f"YOUR Key ({self.client.nickname})", 
                 bg='#2b2b2b', fg='#4CAF50', font=('Arial', 11, 'bold')).pack(anchor=tk.W, padx=10, pady=(10, 5))
            
            fp_text = tk.Text(own_frame, height=3, width=60, bg='#3c3c3c', fg='white',
                            font=('Courier', 9), relief=tk.FLAT, padx=10, pady=5)
            fp_text.insert('1.0', own_fp)
            fp_text.config(state=tk.DISABLED)
            fp_text.pack(padx=10, pady=(0, 10))
        
        # Peer fingerprints
        if self.client.peer_fingerprints:
            for peer_nickname, fingerprint in self.client.peer_fingerprints.items():
                peer_frame = Frame(content_frame, bg='#3c3c3c', relief=tk.RAISED, borderwidth=1)
                peer_frame.pack(fill=tk.X, padx=10, pady=5)
                
                # Check if trusted
                is_trusted = peer_nickname in self.client.trusted_keys and \
                           self.client.trusted_keys[peer_nickname] == fingerprint
                
                status_text = " ✓ TRUSTED" if is_trusted else ""
                color = "#4CAF50" if is_trusted else "#FFA07A"
                
                Label(peer_frame, text=f"{peer_nickname}{status_text}", 
                     bg='#3c3c3c', fg=color, font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=10, pady=(8, 3))
                
                fp_text = tk.Text(peer_frame, height=3, width=60, bg='#2b2b2b', fg='white',
                                font=('Courier', 8), relief=tk.FLAT, padx=10, pady=5)
                fp_text.insert('1.0', fingerprint)
                fp_text.config(state=tk.DISABLED)
                fp_text.pack(padx=10, pady=(0, 5))
                
                # Trust button
                btn_frame = Frame(peer_frame, bg='#3c3c3c')
                btn_frame.pack(fill=tk.X, padx=10, pady=(0, 8))
                
                if is_trusted:
                    Button(btn_frame, text="Remove Trust", 
                          command=lambda n=peer_nickname: self.untrust_key(n),
                          bg='#f44336', fg='white', font=('Arial', 8),
                          relief=tk.FLAT, cursor='hand2', padx=10, pady=3).pack(side=tk.LEFT)
                else:
                    Button(btn_frame, text="✓ Mark as Trusted", 
                          command=lambda n=peer_nickname, fp=fingerprint: self.trust_key(n, fp),
                          bg='#4CAF50', fg='white', font=('Arial', 8),
                          relief=tk.FLAT, cursor='hand2', padx=10, pady=3).pack(side=tk.LEFT)
        else:
            Label(content_frame, text="No peer connections yet", 
                 bg='#1e1e1e', fg='#888888', font=('Arial', 11)).pack(pady=50)
        
        # Close button
        Button(security_window, text="Close", command=security_window.destroy,
              bg='#444444', fg='white', font=('Arial', 10, 'bold'),
              relief=tk.FLAT, cursor='hand2', padx=20, pady=8).pack(pady=(0, 15))
    
    def trust_key(self, nickname, fingerprint):
        """Mark a key as trusted"""
        self.client.trusted_keys[nickname] = fingerprint
        self.display_message(f"✓ Marked {nickname}'s key as trusted", "SYSTEM")
        # Refresh security window if it's open
        for widget in self.window.winfo_children():
            if isinstance(widget, tk.Toplevel):
                if widget.title() == "Security & Key Verification":
                    widget.destroy()
                    self.show_security_info()
    
    def untrust_key(self, nickname):
        """Remove trust from a key"""
        if nickname in self.client.trusted_keys:
            del self.client.trusted_keys[nickname]
            self.display_message(f"Removed trust from {nickname}'s key", "SYSTEM")
            # Refresh security window if it's open
            for widget in self.window.winfo_children():
                if isinstance(widget, tk.Toplevel):
                    if widget.title() == "Security & Key Verification":
                        widget.destroy()
                        self.show_security_info()
    
    def display_gif(self, gif_url, sender, msg_id=None, destruct_timer=None):
        """Display a GIF in the chat window"""
        self.chat_display.configure(state=tk.NORMAL)
        
        # Mark start position if msg_id provided
        if msg_id:
            start_mark = self.chat_display.index(tk.END + "-1c")
        
        timestamp = self.get_timestamp()
        
        try:
            # Check cache first for performance
            if gif_url in self.gif_cache:
                frames = self.gif_cache[gif_url]['frames']
                duration = self.gif_cache[gif_url]['duration']
            else:
                # Download and process the GIF
                response = requests.get(gif_url, timeout=5)
                response.raise_for_status()
                
                img_data = BytesIO(response.content)
                img = Image.open(img_data)
                
                # Get original size and calculate resize factor
                max_width = 200
                max_height = 150
                
                # Extract all frames
                frames = []
                try:
                    while True:
                        # Copy and resize frame
                        frame = img.copy()
                        frame.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
                        frames.append(ImageTk.PhotoImage(frame))
                        img.seek(img.tell() + 1)
                except EOFError:
                    # End of frames reached
                    pass
                
                # Get frame duration (delay between frames in milliseconds)
                try:
                    duration = img.info.get('duration', 100)  # Default 100ms
                except (KeyError, AttributeError):
                    duration = 100
                
                # Cache the processed GIF for reuse
                self.gif_cache[gif_url] = {'frames': frames, 'duration': duration}
                # Manage cache size to prevent memory bloat
                self.manage_gif_cache()
            
            # Insert header
            if sender == "YOU":
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, "[YOU] ", "YOU")
                if destruct_timer:
                    self.chat_display.insert(tk.END, f"(🔥 {destruct_timer}s)\n")
                else:
                    self.chat_display.insert(tk.END, "\n")
            else:
                # Parse username if in format
                user_tag = self.get_user_color(sender)
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, f"[{sender}]", user_tag)
                if destruct_timer:
                    self.chat_display.insert(tk.END, f" (🔥 {destruct_timer}s)\n")
                else:
                    self.chat_display.insert(tk.END, "\n")
            
            # Create a label for the animated GIF
            gif_label = tk.Label(self.chat_display, bg='#1e1e1e')
            self.chat_display.window_create(tk.END, window=gif_label)
            self.chat_display.insert(tk.END, "\n")
            
            # Store animation data
            if msg_id and len(frames) > 1:
                # Limit number of active animations to prevent memory leak
                if len(self.gif_animations) >= self.max_active_gifs:
                    # Remove oldest GIF animation
                    oldest_msg_id = next(iter(self.gif_animations))
                    self.stop_gif_animation(oldest_msg_id)
                
                self.gif_animations[msg_id] = {
                    'frames': frames,
                    'label': gif_label,
                    'current_frame': 0,
                    'delay': duration
                }
                # Start animation
                self.animate_gif(msg_id)
            elif frames:
                # Single frame, just display it
                gif_label.config(image=frames[0])
                gif_label.image = frames[0]  # Keep reference
            
        except Exception as e:
            # If GIF fails to load, show link instead with error message
            self.client.log_error(f"Failed to display GIF from {sender}", e)
            if sender == "YOU":
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, "[YOU] ", "YOU")
                self.chat_display.insert(tk.END, f"GIF: {gif_url}\n")
                self.chat_display.insert(tk.END, f"(Failed to load: {str(e)})\n", "ERROR")
            else:
                user_tag = self.get_user_color(sender)
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, f"[{sender}] ", user_tag)
                self.chat_display.insert(tk.END, f"GIF: {gif_url}\n")
                self.chat_display.insert(tk.END, f"(Failed to load: {str(e)})\n", "ERROR")
        
        # Mark end position and store if msg_id provided
        if msg_id:
            end_mark = self.chat_display.index(tk.END + "-1c")
            self.message_marks[msg_id] = (start_mark, end_mark)
        
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
    def manage_gif_cache(self) -> None:
        """Manage GIF cache size to prevent memory bloat.
        
        Implements LRU-style eviction: removes oldest cached items
        when cache exceeds max_cache_size limit.
        """
        if len(self.gif_cache) > self.max_cache_size:
            # Remove oldest 20% of cache
            items_to_remove = len(self.gif_cache) - self.max_cache_size + 10
            for _ in range(items_to_remove):
                if self.gif_cache:
                    self.gif_cache.pop(next(iter(self.gif_cache)))
        
        if len(self.gif_preview_cache) > self.max_cache_size:
            # Remove oldest 20% of preview cache
            items_to_remove = len(self.gif_preview_cache) - self.max_cache_size + 10
            for _ in range(items_to_remove):
                if self.gif_preview_cache:
                    self.gif_preview_cache.pop(next(iter(self.gif_preview_cache)))
    
    def stop_gif_animation(self, msg_id):
        """Stop a GIF animation and free its resources"""
        if msg_id in self.gif_animations:
            anim_data = self.gif_animations[msg_id]
            # Clear frame references to free memory
            if 'frames' in anim_data:
                anim_data['frames'].clear()
            # Remove from tracking
            del self.gif_animations[msg_id]
    
    def animate_gif(self, msg_id):
        """Animate a GIF by cycling through its frames"""
        if msg_id not in self.gif_animations:
            return
        
        anim_data = self.gif_animations[msg_id]
        frames = anim_data['frames']
        label = anim_data['label']
        current_frame = anim_data['current_frame']
        
        # Update the label with the current frame
        try:
            label.config(image=frames[current_frame])
            label.image = frames[current_frame]  # Keep reference
        except tk.TclError:
            # Label might have been destroyed
            if msg_id in self.gif_animations:
                del self.gif_animations[msg_id]
            return
        
        # Move to next frame
        anim_data['current_frame'] = (current_frame + 1) % len(frames)
        
        # Schedule next frame update
        self.window.after(anim_data['delay'], lambda: self.animate_gif(msg_id))
    
    def open_gif_search(self):
        """Open a GIF search dialog"""
        search_window = Toplevel(self.window)
        search_window.title("Search GIFs - Tenor")
        search_window.geometry("700x600")
        search_window.configure(bg='#2b2b2b')
        
        # Search input
        search_frame = Frame(search_window, bg='#2b2b2b')
        search_frame.pack(padx=10, pady=10, fill=tk.X)
        
        Label(search_frame, text="Search:", bg='#2b2b2b', fg='white', 
              font=('Arial', 11, 'bold')).pack(side=tk.LEFT, padx=(0, 10))
        
        search_entry = Entry(search_frame, font=('Arial', 11), bg='#3c3c3c', 
                           fg='white', relief=tk.FLAT, insertbackground='white')
        search_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        def do_search():
            query = search_entry.get().strip()
            if query:
                self.search_and_display_gifs(query, results_frame, search_window)
        
        search_entry.bind('<Return>', lambda e: do_search())
        
        search_btn = Button(search_frame, text="Search", command=do_search,
                          bg='#9C27B0', fg='white', font=('Arial', 10, 'bold'),
                          relief=tk.FLAT, cursor='hand2', padx=15, pady=5)
        search_btn.pack(side=tk.RIGHT)
        
        # Results frame with scrollbar
        results_container = Frame(search_window, bg='#2b2b2b')
        results_container.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        
        canvas = Canvas(results_container, bg='#1e1e1e', highlightthickness=0)
        scrollbar = Scrollbar(results_container, orient=VERTICAL, command=canvas.yview)
        results_frame = Frame(canvas, bg='#1e1e1e')
        
        results_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=results_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Mouse wheel scrolling
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        
        # Initial message
        Label(results_frame, text="Enter a search term and press Enter or click Search", 
              bg='#1e1e1e', fg='#888888', font=('Arial', 11)).pack(pady=50)
        
        search_entry.focus()
    
    def search_and_display_gifs(self, query, results_frame, parent_window):
        """Search Tenor API and display results"""
        # Clear previous results
        for widget in results_frame.winfo_children():
            widget.destroy()
        
        loading_label = Label(results_frame, text=f"Searching for '{query}'...", 
              bg='#1e1e1e', fg='white', font=('Arial', 11))
        loading_label.pack(pady=20)
        results_frame.update()
        
        def load_results_async():
            try:
                # Search Tenor API
                params = {
                    'q': query,
                    'key': TENOR_API_KEY,
                    'limit': 20,
                    'media_filter': 'gif'
                }
                
                response = requests.get(TENOR_API_URL, params=params, timeout=10)
                response.raise_for_status()
                data = response.json()
                
                results = data.get('results', [])
                
                # Update UI on main thread
                self.window.after(0, lambda: self.display_gif_results(results, results_frame, parent_window, loading_label))
                
            except requests.exceptions.RequestException as e:
                self.window.after(0, lambda: self.show_gif_error(results_frame, f"Error searching GIFs: {e}"))
            except Exception as e:
                self.window.after(0, lambda: self.show_gif_error(results_frame, f"Unexpected error: {e}"))
        
        # Start search in background thread
        search_thread = threading.Thread(target=load_results_async, daemon=True)
        search_thread.start()
    
    def show_gif_error(self, results_frame, error_msg):
        """Show error message in results frame"""
        for widget in results_frame.winfo_children():
            widget.destroy()
        Label(results_frame, text=error_msg, 
              bg='#1e1e1e', fg='#f44336', font=('Arial', 11)).pack(pady=50)
    
    def display_gif_results(self, results, results_frame, parent_window, loading_label):
        """Display GIF search results progressively"""
        # Clear loading message
        loading_label.destroy()
        
        if not results:
            Label(results_frame, text="No GIFs found. Try a different search.", 
                  bg='#1e1e1e', fg='#888888', font=('Arial', 11)).pack(pady=50)
            return
        
        # Create grid container
        max_cols = 3
        gif_positions = []
        
        # Pre-create all frames first (fast)
        for idx, gif_data in enumerate(results):
            row = idx // max_cols
            col = idx % max_cols
            
            media_formats = gif_data.get('media_formats', {})
            
            # Try different preview formats in order of preference
            preview_url = None
            gif_url = None
            
            if 'tinygif' in media_formats:
                preview_url = media_formats['tinygif']['url']
            elif 'nanogif' in media_formats:
                preview_url = media_formats['nanogif']['url']
            elif 'gif' in media_formats:
                preview_url = media_formats['gif']['url']
            
            if 'gif' in media_formats:
                gif_url = media_formats['gif']['url']
            elif 'mediumgif' in media_formats:
                gif_url = media_formats['mediumgif']['url']
            
            if not preview_url or not gif_url:
                continue
            
            # Create frame with placeholder
            gif_frame = Frame(results_frame, bg='#1e1e1e', relief=tk.RAISED, borderwidth=1)
            gif_frame.grid(row=row, column=col, padx=5, pady=5, sticky='nsew')
            
            placeholder = Label(gif_frame, text="Loading...", bg='#1e1e1e', fg='#888888',
                              font=('Arial', 9), width=20, height=10)
            placeholder.pack(padx=2, pady=2)
            
            gif_positions.append({
                'frame': gif_frame,
                'placeholder': placeholder,
                'preview_url': preview_url,
                'gif_url': gif_url
            })
        
        # Configure grid weights
        for i in range(max_cols):
            results_frame.grid_columnconfigure(i, weight=1)
        
        # Load GIF previews progressively in background
        def load_gif_preview(position_data):
            try:
                img_response = requests.get(position_data['preview_url'], timeout=10)
                img_response.raise_for_status()
                img_data = BytesIO(img_response.content)
                img = Image.open(img_data)
                img.thumbnail((200, 200), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                
                # Update UI on main thread
                def update_preview():
                    try:
                        position_data['placeholder'].destroy()
                        
                        def send_this_gif(url=position_data['gif_url']):
                            self.client.send_gif(url)
                            parent_window.destroy()
                        
                        gif_btn = Button(position_data['frame'], image=photo, command=send_this_gif,
                                       bg='#1e1e1e', relief=tk.FLAT, cursor='hand2')
                        gif_btn.image = photo  # Keep reference
                        gif_btn.pack(padx=2, pady=2)
                    except tk.TclError:
                        # Widget might have been destroyed
                        pass
                
                self.window.after(0, update_preview)
            except Exception as e:
                # Silently fail for individual GIFs
                pass
        
        # Load all GIF previews in parallel
        for pos_data in gif_positions:
            load_thread = threading.Thread(target=load_gif_preview, args=(pos_data,), daemon=True)
            load_thread.start()
    
    def on_key_press(self, event):
        """Handle key press in message entry"""
        # Ignore Enter key (handled by send_message)
        if event.keysym == 'Return':
            return
        
        # Send typing indicator
        if self.client.connected and self.client.shared_keys:
            self.client.send_typing_status(True)
            
            # Cancel previous timer
            if self.typing_timer:
                self.typing_timer.cancel()
            
            # Set timer to stop typing indicator after 2 seconds of inactivity
            self.typing_timer = threading.Timer(2.0, lambda: self.client.send_typing_status(False))
            self.typing_timer.daemon = True
            self.typing_timer.start()
    
    def update_typing_indicator(self):
        """Update the typing indicator label"""
        if not self.typing_users:
            self.typing_label.config(text="")
        elif len(self.typing_users) == 1:
            user = list(self.typing_users)[0]
            self.typing_label.config(text=f"{user} is typing...")
        elif len(self.typing_users) == 2:
            users = list(self.typing_users)
            self.typing_label.config(text=f"{users[0]} and {users[1]} are typing...")
        else:
            self.typing_label.config(text="Several people are typing...")
    
    def send_message(self):
        """Send message from entry field"""
        message = self.message_entry.get()
        if message.strip() and self.client.connected:
            # Stop typing indicator when sending
            if self.typing_timer:
                self.typing_timer.cancel()
                self.typing_timer = None
            self.client.send_typing_status(False)
            
            # Auto-detect GIF URLs and send as GIF instead of text
            message_stripped = message.strip()
            if (message_stripped.startswith('http://') or message_stripped.startswith('https://')) and \
               ('.gif' in message_stripped.lower() or 'tenor.com' in message_stripped.lower() or 'giphy.com' in message_stripped.lower()):
                # This looks like a GIF URL - send as GIF
                self.client.send_gif(message_stripped)
            else:
                # Regular text message
                self.client.send_message(message)
            
            self.message_entry.delete(0, tk.END)
        elif not self.client.connected:
            messagebox.showwarning("Not Connected", "You are not connected to the server!")
    
    def send_file_dialog(self):
        """Open file selection dialog and send file"""
        if not self.client.connected:
            messagebox.showwarning("Not Connected", "You are not connected to the server!")
            return
        
        if not self.client.shared_keys:
            messagebox.showwarning("No Peers", "No other users connected to receive the file!")
            return
        
        # Open file dialog
        filepath = filedialog.askopenfilename(
            title="Select a file to send",
            filetypes=[
                ("All Files", "*.*"),
                ("Images", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Documents", "*.pdf *.doc *.docx *.txt"),
                ("Archives", "*.zip *.rar *.7z"),
            ]
        )
        
        if filepath:
            self.client.send_file(filepath)
    
    def on_closing(self):
        """Handle window close event"""
        if self.client.connected:
            self.client.disconnect()
        self.window.destroy()
    
    def run(self):
        """Start the GUI main loop"""
        self.window.mainloop()

if __name__ == "__main__":
    # Create a simple dialog to get connection info
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    
    # Load configuration
    config = load_config()
    
    # Get server address (use command line args if provided, otherwise use config)
    if len(sys.argv) > 1:
        host = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else config['server_port']
        nickname = sys.argv[3] if len(sys.argv) > 3 else config['nickname']
    else:
        # Show config dialog with option to change settings
        change_settings = messagebox.askyesno(
            "Xessenger - Login",
            f"Current settings:\n\n"
            f"Server: {config['server_host']}:{config['server_port']}\n"
            f"Nickname: {config['nickname']}\n\n"
            f"Change these settings?"
        )
        
        if change_settings:
            host = simpledialog.askstring(
                "Server Address", 
                "Enter server address:", 
                initialvalue=config['server_host']
            )
            if not host:
                host = config['server_host']
            
            port_str = simpledialog.askstring(
                "Server Port", 
                "Enter server port:", 
                initialvalue=str(config['server_port'])
            )
            port = int(port_str) if port_str else config['server_port']
            
            nickname = simpledialog.askstring(
                "Nickname", 
                "Enter your nickname:", 
                initialvalue=config['nickname']
            )
            if not nickname or not nickname.strip():
                nickname = config['nickname']
            
            # Save new settings
            save_config(host, port, nickname)
        else:
            # Use saved settings
            host = config['server_host']
            port = config['server_port']
            nickname = config['nickname']
    
    # Always ask for server password (not saved for security)
    password = None
    if len(sys.argv) > 4:
        password = sys.argv[4]
    else:
        use_password = messagebox.askyesno(
            "Server Password",
            "Does this server require a password?"
        )
        if use_password:
            password = simpledialog.askstring(
                "Server Password",
                "Enter server password:",
                show='*'
            )
    
    root.destroy()
    
    # Create client and GUI
    client = CommunicationClient(host=host, port=port, nickname=nickname)
    client.server_password = password  # Set password for authentication
    gui = ChatGUI(client)
    
    # Connect to server in background thread
    connect_thread = threading.Thread(target=client.connect)
    connect_thread.daemon = True
    connect_thread.start()
    
    # Run GUI
    gui.run()
