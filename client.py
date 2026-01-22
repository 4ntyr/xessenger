"""
Simple PC-to-PC Communication Client
GUI Application with Encryption
"""

import socket
import threading
import sys
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, Toplevel, Label, Entry, Button, Frame, Canvas, Scrollbar, VERTICAL, HORIZONTAL
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

# Tenor API configuration
TENOR_API_KEY = "AIzaSyAyimkuYQYF_FXVALexPuGQctUWRURdCYQ"  # Default key, users should get their own
TENOR_API_URL = "https://tenor.googleapis.com/v2/search"

class CommunicationClient:
    def __init__(self, host='localhost', port=5000, nickname='User'):
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
        self.pending_messages = []  # Messages waiting for key exchange
        self.message_timers = {}  # msg_id -> threading.Timer for self-destruct
    
    def generate_dh_parameters(self):
        """Generate Diffie-Hellman parameters (shared by all clients)"""
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
    
    def generate_dh_keys(self):
        """Generate Diffie-Hellman key pair"""
        if not self.dh_parameters:
            self.generate_dh_parameters()
        self.dh_private_key = self.dh_parameters.generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
    
    def serialize_public_key(self):
        """Serialize public key for transmission"""
        return self.dh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def derive_shared_key(self, peer_public_key_bytes):
        """Derive shared encryption key from peer's public key"""
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        
        shared_secret = self.dh_private_key.exchange(peer_public_key)
        
        # Derive a Fernet-compatible key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'e2e-chat-encryption'
        ).derive(shared_secret)
        
        return base64.urlsafe_b64encode(derived_key)
        
    def connect(self):
        """Connect to the communication server"""
        try:
            # Generate DH keys for E2E encryption
            self.generate_dh_keys()
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
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
            
        except ConnectionRefusedError:
            error_msg = f"Could not connect to {self.host}:{self.port}"
            if self.gui:
                self.gui.display_message(error_msg, "ERROR")
                messagebox.showerror("Connection Error", error_msg)
            self.connected = False
        except Exception as e:
            error_msg = f"Connection error: {e}"
            if self.gui:
                self.gui.display_message(error_msg, "ERROR")
                messagebox.showerror("Connection Error", error_msg)
            self.connected = False
    
    def send_message(self, message):
        """Send an encrypted message to all peers"""
        try:
            if self.connected and message.strip():
                if not self.shared_keys:
                    if self.gui:
                        self.gui.display_message("Waiting for other clients to join...", "SYSTEM")
                    return
                
                # Check for /d command (self-destruct)
                destruct_timer = None
                actual_message = message
                
                if message.startswith("/d "):
                    parts = message.split(" ", 2)
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
                
                # Generate unique message ID
                msg_id = str(uuid.uuid4())
                
                # Get reply data if replying
                reply_data = None
                if self.gui and self.gui.reply_to:
                    reply_data = self.gui.reply_to.copy()
                
                # Encrypt message for each peer with their shared key
                encrypted_messages = {}
                for peer_nickname, shared_key in self.shared_keys.items():
                    cipher = Fernet(shared_key)
                    encrypted_msg = cipher.encrypt(actual_message.encode('utf-8')).decode('utf-8')
                    encrypted_messages[peer_nickname] = encrypted_msg
                
                # Prepare packet
                msg_packet = {
                    "type": "DESTRUCT_MSG" if destruct_timer else "MSG",
                    "from": self.nickname,
                    "encrypted_messages": encrypted_messages,
                    "msg_id": msg_id
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
    
    def receive_messages(self):
        """Receive messages from the server"""
        buffer = ""
        try:
            while self.connected:
                data = self.socket.recv(4096)
                
                if not data:
                    break
                
                buffer += data.decode('utf-8')
                
                # Process complete JSON packets (newline-delimited)
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    if line.strip():
                        try:
                            packet = json.loads(line)
                            self.handle_packet(packet)
                        except json.JSONDecodeError as e:
                            if self.gui:
                                self.gui.display_message(f"Invalid packet received", "ERROR")
                
        except Exception as e:
            if self.connected:
                error_msg = f"Error receiving message: {e}"
                if self.gui:
                    self.gui.display_message(error_msg, "ERROR")
    
    def handle_packet(self, packet):
        """Handle different packet types"""
        try:
            packet_type = packet.get("type")
            
            if packet_type == "PUBKEY":
                # Received public key from another client
                peer_nickname = packet.get("nickname")
                public_key_pem = packet.get("public_key")
                
                if peer_nickname != self.nickname:
                    # Store peer's public key
                    self.peer_public_keys[peer_nickname] = public_key_pem.encode('utf-8')
                    
                    # Derive shared key
                    shared_key = self.derive_shared_key(public_key_pem.encode('utf-8'))
                    self.shared_keys[peer_nickname] = shared_key
                    
                    if self.gui:
                        self.gui.display_message(
                            f"🔒 Secure connection established with {peer_nickname}",
                            "SYSTEM"
                        )
            
            elif packet_type == "MSG" or packet_type == "DESTRUCT_MSG":
                # Received encrypted message
                sender = packet.get("from")
                encrypted_messages = packet.get("encrypted_messages", {})
                msg_id = packet.get("msg_id")
                destruct_timer = packet.get("destruct_timer")
                reply_to = packet.get("reply_to")
                
                # Find our encrypted message
                if self.nickname in encrypted_messages:
                    encrypted_msg = encrypted_messages[self.nickname]
                    
                    # Decrypt using shared key with sender
                    if sender in self.shared_keys:
                        cipher = Fernet(self.shared_keys[sender])
                        decrypted_msg = cipher.decrypt(encrypted_msg.encode('utf-8')).decode('utf-8')
                        
                        # Format for display
                        formatted_msg = f"[{sender}]: {decrypted_msg}"
                        if destruct_timer:
                            formatted_msg = f"[{sender}]: {decrypted_msg} 🔥 ({destruct_timer}s)"
                        
                        if self.gui:
                            self.gui.display_message(formatted_msg, "RECEIVED", msg_id=msg_id, reply_to=reply_to)
                            
                            # Schedule deletion if self-destruct
                            if destruct_timer:
                                timer = threading.Timer(destruct_timer, self.delete_message, args=[msg_id])
                                timer.daemon = True
                                timer.start()
                                self.message_timers[msg_id] = timer
                    else:
                        if self.gui:
                            self.gui.display_message(
                                f"Cannot decrypt message from {sender} - no shared key",
                                "ERROR"
                            )
            
            elif packet_type == "GIF_MSG" or packet_type == "DESTRUCT_GIF_MSG":
                # Received encrypted GIF message
                sender = packet.get("from")
                encrypted_gifs = packet.get("encrypted_gifs", {})
                msg_id = packet.get("msg_id")
                destruct_timer = packet.get("destruct_timer")
                
                # Find our encrypted GIF
                if self.nickname in encrypted_gifs:
                    encrypted_url = encrypted_gifs[self.nickname]
                    
                    # Decrypt using shared key with sender
                    if sender in self.shared_keys:
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
                    else:
                        if self.gui:
                            self.gui.display_message(
                                f"Cannot decrypt GIF from {sender} - no shared key",
                                "ERROR"
                            )
            
            elif packet_type == "SYSTEM":
                # System message from server
                sys_msg = packet.get("message", "")
                if self.gui:
                    self.gui.display_message(sys_msg, "SYSTEM")
            
            elif packet_type == "USER_LEFT":
                # User disconnected
                left_user = packet.get("nickname")
                if left_user in self.shared_keys:
                    del self.shared_keys[left_user]
                if left_user in self.peer_public_keys:
                    del self.peer_public_keys[left_user]
                if self.gui:
                    self.gui.display_message(f"{left_user} left the chat", "SYSTEM")
                    
        except Exception as e:
            if self.gui:
                self.gui.display_message(f"Error handling packet: {e}", "ERROR")
    
    def disconnect(self):
        """Disconnect from the server"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
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
        self.color_palette = [
            "#FF6B6B", "#4ECDC4", "#45B7D1", "#FFA07A", "#98D8C8",
            "#F7DC6F", "#BB8FCE", "#85C1E2", "#F8B739", "#52B788",
            "#FFD93D", "#6BCF7F", "#C490E4", "#F4A460", "#87CEEB"
        ]
        self.next_color_index = 0
        self.window_focused = True  # Track if window has focus
        
        self.window = tk.Tk()
        self.window.title(f"Chat Client - {self.client.nickname}")
        self.window.geometry("600x500")
        self.window.configure(bg='#2b2b2b')
        
        # Chat display area
        chat_frame = tk.Frame(self.window, bg='#2b2b2b')
        chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Header with title and clear button
        header_frame = tk.Frame(chat_frame, bg='#2b2b2b')
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        tk.Label(header_frame, text="Chat Messages", bg='#2b2b2b', fg='white', 
                font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        
        self.clear_button = tk.Button(
            header_frame,
            text="🗑️ Clear Chat",
            command=self.clear_chat,
            bg='#444444',
            fg='white',
            font=('Arial', 9),
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
        
        tk.Label(input_frame, text="Your Message", bg='#2b2b2b', fg='white',
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
            font=('Arial', 10, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=8
        )
        self.gif_button.pack(side=tk.RIGHT, padx=(0, 10))
        
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
    
    def show_notification(self, username, message_preview):
        """Show Windows notification for new message"""
        try:
            toast = Notification(
                app_id="Chat Client",
                title=f"New message from {username}",
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
            pass
    
    def bring_to_front(self):
        """Bring window to front and focus it"""
        try:
            self.window.lift()
            self.window.focus_force()
            self.window.attributes('-topmost', True)
            self.window.after(100, lambda: self.window.attributes('-topmost', False))
        except:
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
            self.chat_display.insert(tk.END, f"{message}\n")
        elif tag == "RECEIVED":
            # Parse username from message format "[username]: message"
            if message.startswith("[") and "]:" in message:
                bracket_end = message.index("]")
                username = message[1:bracket_end]
                rest_of_message = message[bracket_end+1:].lstrip(":")
                sender = username
                message_text = rest_of_message.strip()
                
                # Show notification if window is not focused
                if not self.window_focused:
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
                self.chat_display.insert(tk.END, f": {message_text}\n")
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
        self.cancel_reply()
        self.display_message("Chat cleared", "SYSTEM")
    
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
    
    def display_gif(self, gif_url, sender, msg_id=None, destruct_timer=None):
        """Display a GIF in the chat window"""
        self.chat_display.configure(state=tk.NORMAL)
        
        # Mark start position if msg_id provided
        if msg_id:
            start_mark = self.chat_display.index(tk.END + "-1c")
        
        timestamp = self.get_timestamp()
        
        try:
            # Download and display the GIF
            response = requests.get(gif_url, timeout=5)
            response.raise_for_status()
            
            img_data = BytesIO(response.content)
            img = Image.open(img_data)
            
            # Resize if too large
            max_width = 400
            max_height = 300
            img.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
            
            photo = ImageTk.PhotoImage(img)
            
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
            
            # Insert the image
            self.chat_display.image_create(tk.END, image=photo)
            self.chat_display.insert(tk.END, "\n")
            
            # Keep a reference to prevent garbage collection
            if not hasattr(self, 'gif_images'):
                self.gif_images = []
            self.gif_images.append(photo)
            
        except Exception as e:
            # If GIF fails to load, show link instead
            if sender == "YOU":
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, "[YOU] ", "YOU")
                self.chat_display.insert(tk.END, f"GIF: {gif_url}\n")
            else:
                user_tag = self.get_user_color(sender)
                self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
                self.chat_display.insert(tk.END, f"[{sender}] ", user_tag)
                self.chat_display.insert(tk.END, f"GIF: {gif_url}\n")
        
        # Mark end position and store if msg_id provided
        if msg_id:
            end_mark = self.chat_display.index(tk.END + "-1c")
            self.message_marks[msg_id] = (start_mark, end_mark)
        
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)
    
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
        
        Label(results_frame, text=f"Searching for '{query}'...", 
              bg='#1e1e1e', fg='white', font=('Arial', 11)).pack(pady=20)
        results_frame.update()
        
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
            
            # Clear loading message
            for widget in results_frame.winfo_children():
                widget.destroy()
            
            results = data.get('results', [])
            
            if not results:
                Label(results_frame, text="No GIFs found. Try a different search.", 
                      bg='#1e1e1e', fg='#888888', font=('Arial', 11)).pack(pady=50)
                return
            
            # Display GIFs in a grid
            row = 0
            col = 0
            max_cols = 3
            loaded_count = 0
            
            for gif_data in results:
                try:
                    # Get GIF URL (use smaller preview for display)
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
                    
                    # Create frame for this GIF
                    gif_frame = Frame(results_frame, bg='#1e1e1e', relief=tk.RAISED, borderwidth=1)
                    gif_frame.grid(row=row, column=col, padx=5, pady=5, sticky='nsew')
                    
                    # Load preview image
                    img_response = requests.get(preview_url, timeout=10)
                    img_response.raise_for_status()
                    img_data = BytesIO(img_response.content)
                    img = Image.open(img_data)
                    img.thumbnail((200, 200), Image.Resampling.LANCZOS)
                    photo = ImageTk.PhotoImage(img)
                    
                    # Create button with image
                    def send_this_gif(url=gif_url):
                        self.client.send_gif(url)
                        parent_window.destroy()
                    
                    gif_btn = Button(gif_frame, image=photo, command=send_this_gif,
                                   bg='#1e1e1e', relief=tk.FLAT, cursor='hand2')
                    gif_btn.image = photo  # Keep reference
                    gif_btn.pack(padx=2, pady=2)
                    
                    loaded_count += 1
                    col += 1
                    if col >= max_cols:
                        col = 0
                        row += 1
                        
                except Exception as e:
                    # Print error for debugging but continue loading others
                    print(f"Failed to load GIF preview: {e}")
                    continue
            
            # If no GIFs loaded, show error
            if loaded_count == 0:
                Label(results_frame, text="Failed to load GIF previews. Check your internet connection.", 
                      bg='#1e1e1e', fg='#f44336', font=('Arial', 11)).pack(pady=50)
            
            # Configure grid weights
            for i in range(max_cols):
                results_frame.grid_columnconfigure(i, weight=1)
                
        except requests.exceptions.RequestException as e:
            for widget in results_frame.winfo_children():
                widget.destroy()
            Label(results_frame, text=f"Error searching GIFs: {e}", 
                  bg='#1e1e1e', fg='#f44336', font=('Arial', 11)).pack(pady=50)
        except Exception as e:
            for widget in results_frame.winfo_children():
                widget.destroy()
            Label(results_frame, text=f"Unexpected error: {e}", 
                  bg='#1e1e1e', fg='#f44336', font=('Arial', 11)).pack(pady=50)
    
    def send_message(self):
        """Send message from entry field"""
        message = self.message_entry.get()
        if message.strip() and self.client.connected:
            self.client.send_message(message)
            self.message_entry.delete(0, tk.END)
        elif not self.client.connected:
            messagebox.showwarning("Not Connected", "You are not connected to the server!")
    
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
    
    # Get server address
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = simpledialog.askstring("Server Address", 
                                     "Enter server address:", 
                                     initialvalue="localhost")
        if not host:
            host = "localhost"
    
    # Get port
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port_str = simpledialog.askstring("Server Port", 
                                         "Enter server port:", 
                                         initialvalue="5000")
        port = int(port_str) if port_str else 5000
    
    # Get nickname
    if len(sys.argv) > 3:
        nickname = sys.argv[3]
    else:
        nickname = simpledialog.askstring("Nickname", 
                                         "Enter your nickname:", 
                                         initialvalue="User")
        if not nickname or not nickname.strip():
            nickname = "Anonymous"
    
    root.destroy()
    
    # Create client and GUI
    client = CommunicationClient(host=host, port=port, nickname=nickname)
    gui = ChatGUI(client)
    
    # Connect to server in background thread
    connect_thread = threading.Thread(target=client.connect)
    connect_thread.daemon = True
    connect_thread.start()
    
    # Run GUI
    gui.run()
