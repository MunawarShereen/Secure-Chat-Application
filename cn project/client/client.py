import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Frame, Menu
import socket
import threading
import json
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import time
from uuid import uuid4

# Server configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
BUFFER_SIZE = 4096
AES_BLOCK_SIZE = 16

class SecureChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Application")
        self.root.geometry("700x550")
        self.root.resizable(False, False)
        
        # Client state
        self.socket = None
        self.username = None
        self.session_key = None
        self.running = False
        self.message_history = {}  # {message_id: (sender, message, timestamp)}
        self.currently_selected = None
        self.currently_editing = None
        self.last_highlighted = None  # To track highlighted message
        
        # Create container frame
        self.container = Frame(root)
        self.container.pack(fill="both", expand=True)
        
        # Create all frames
        self.create_welcome_frame()
        self.create_login_frame()
        self.create_register_frame()
        self.create_chat_frame()
        
        # Start with welcome frame
        self.show_frame("welcome")
    
    def create_welcome_frame(self):
        """Create the welcome frame with login and register options"""
        self.welcome_frame = Frame(self.container)
        
        # Title
        ttk.Label(self.welcome_frame, text="Welcome to Secure Chat", font=('Helvetica', 16)).pack(pady=30)
        
        # Buttons
        ttk.Button(self.welcome_frame, text="Login", command=lambda: self.show_frame("login"),
                  width=20).pack(pady=10)
        ttk.Button(self.welcome_frame, text="Register", command=lambda: self.show_frame("register"),
                  width=20).pack(pady=10)
        
        # Status
        self.welcome_status = ttk.Label(self.welcome_frame, text="", foreground="red")
        self.welcome_status.pack(pady=10)
    
    def create_login_frame(self):
        """Create the login frame"""
        self.login_frame = Frame(self.container)
        
        # Title
        ttk.Label(self.login_frame, text="Login", font=('Helvetica', 14)).pack(pady=10)
        
        # Username
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.login_username = ttk.Entry(self.login_frame, width=30)
        self.login_username.pack(pady=5)
        
        # Password
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.login_password = ttk.Entry(self.login_frame, width=30, show="*")
        self.login_password.pack(pady=5)
        
        # Buttons
        button_frame = Frame(self.login_frame)
        button_frame.pack(pady=15)
        
        ttk.Button(button_frame, text="Back", command=lambda: self.show_frame("welcome")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Login", command=self.handle_login).pack(side=tk.LEFT, padx=5)
        
        # Status
        self.login_status = ttk.Label(self.login_frame, text="", foreground="red")
        self.login_status.pack(pady=10)
        
        # Bind Enter key to login
        self.login_password.bind('<Return>', lambda event: self.handle_login())
    
    def create_register_frame(self):
        """Create the registration frame"""
        self.register_frame = Frame(self.container)
        
        # Title
        ttk.Label(self.register_frame, text="Register", font=('Helvetica', 14)).pack(pady=10)
        
        # Username
        ttk.Label(self.register_frame, text="Username:").pack(pady=5)
        self.register_username = ttk.Entry(self.register_frame, width=30)
        self.register_username.pack(pady=5)
        
        # Password
        ttk.Label(self.register_frame, text="Password:").pack(pady=5)
        self.register_password = ttk.Entry(self.register_frame, width=30, show="*")
        self.register_password.pack(pady=5)
        
        # Confirm Password
        ttk.Label(self.register_frame, text="Confirm Password:").pack(pady=5)
        self.register_confirm = ttk.Entry(self.register_frame, width=30, show="*")
        self.register_confirm.pack(pady=5)
        
        # Buttons
        button_frame = Frame(self.register_frame)
        button_frame.pack(pady=15)
        
        ttk.Button(button_frame, text="Back", command=lambda: self.show_frame("welcome")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Register", command=self.handle_register).pack(side=tk.LEFT, padx=5)
        
        # Status
        self.register_status = ttk.Label(self.register_frame, text="", foreground="red")
        self.register_status.pack(pady=10)
        
        # Bind Enter key to register
        self.register_confirm.bind('<Return>', lambda event: self.handle_register())
    
    def create_chat_frame(self):
        """Create the chat frame with message editing capabilities"""
        self.chat_frame = Frame(self.container)
        
        # User info and back button
        top_frame = Frame(self.chat_frame)
        top_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(top_frame, text="Back", command=self.disconnect).pack(side=tk.LEFT, padx=5)
        self.user_label = ttk.Label(top_frame, text="", font=('Helvetica', 10))
        self.user_label.pack(side=tk.RIGHT, padx=5)
        
        # Chat display with right-click menu
        self.chat_display = scrolledtext.ScrolledText(
            self.chat_frame, width=80, height=22, state='disabled', wrap=tk.WORD)
        self.chat_display.pack(pady=5)
        
        # Create right-click menu
        self.message_menu = Menu(self.root, tearoff=0)
        self.message_menu.add_command(label="Edit", command=self.start_editing_message)
        
        # Bind right-click event
        self.chat_display.bind("<Button-3>", self.show_message_menu)
        
        # Message entry and edit controls
        entry_frame = Frame(self.chat_frame)
        entry_frame.pack(fill=tk.X, pady=10)
        
        self.message_entry = ttk.Entry(entry_frame, width=70)
        self.message_entry.pack(side=tk.LEFT, padx=5)
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        
        # Edit controls frame (hidden by default)
        self.edit_controls = Frame(entry_frame)
        
        self.save_edit_btn = ttk.Button(self.edit_controls, text="Save", command=self.save_edited_message, width=8)
        self.save_edit_btn.pack(side=tk.LEFT, padx=2)
        
        self.cancel_edit_btn = ttk.Button(self.edit_controls, text="Cancel", command=self.cancel_editing, width=8)
        self.cancel_edit_btn.pack(side=tk.LEFT, padx=2)
        
        # Regular send button
        self.send_btn = ttk.Button(entry_frame, text="Send", command=self.send_message, width=8)
        self.send_btn.pack(side=tk.LEFT)
    
    def show_frame(self, frame_name):
        """Show the specified frame"""
        for frame in [self.welcome_frame, self.login_frame, 
                     self.register_frame, self.chat_frame]:
            frame.pack_forget()
        
        if frame_name == "welcome":
            self.welcome_frame.pack(fill="both", expand=True)
        elif frame_name == "login":
            self.login_frame.pack(fill="both", expand=True)
            self.login_username.focus()
        elif frame_name == "register":
            self.register_frame.pack(fill="both", expand=True)
            self.register_username.focus()
        elif frame_name == "chat":
            self.chat_frame.pack(fill="both", expand=True)
            self.message_entry.focus()
            self.user_label.config(text=f"Logged in as: {self.username}")
            self.show_normal_send_controls()
    
    def handle_register(self):
        """Handle user registration"""
        username = self.register_username.get().strip()
        password = self.register_password.get().strip()
        confirm = self.register_confirm.get().strip()
        
        if not username or not password:
            self.register_status.config(text="Username and password are required")
            return
        
        if password != confirm:
            self.register_status.config(text="Passwords do not match")
            return
        
        try:
            # Create a new socket for registration
            reg_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reg_socket.connect((SERVER_HOST, SERVER_PORT))
            reg_socket.sendall(f"register:{username}:{password}".encode('utf-8'))
            
            response = reg_socket.recv(BUFFER_SIZE).decode('utf-8')
            reg_socket.close()
            
            if "successful" in response.lower():
                messagebox.showinfo("Success", response)
                self.register_username.delete(0, tk.END)
                self.register_password.delete(0, tk.END)
                self.register_confirm.delete(0, tk.END)
                self.register_status.config(text="")
                self.show_frame("login")
            else:
                self.register_status.config(text=response)
        except Exception as e:
            self.register_status.config(text=f"Connection error: {str(e)}")
            if 'reg_socket' in locals():
                reg_socket.close()
    
    def handle_login(self):
        """Handle user login"""
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        
        if not username or not password:
            self.login_status.config(text="Username and password are required")
            return
        
        try:
            # Disable buttons during connection attempt
            for widget in self.login_frame.winfo_children():
                if isinstance(widget, ttk.Button):
                    widget.config(state=tk.DISABLED)
            
            self.login_status.config(text="Connecting...")
            self.root.update()  # Force UI update
            
            # Create new socket for the session
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)  # Set timeout for connection
            self.socket.connect((SERVER_HOST, SERVER_PORT))
            self.socket.settimeout(None)  # Remove timeout after connection
            
            # Send login credentials
            self.socket.sendall(f"login:{username}:{password}".encode('utf-8'))
            
            # Get response (session key)
            response = self.socket.recv(BUFFER_SIZE).decode('utf-8')
            
            try:
                # Try to decode the session key
                self.session_key = base64.b64decode(response.encode('utf-8'))
                if len(self.session_key) != 32:
                    raise ValueError("Invalid key length")
                
                self.username = username
                self.login_status.config(text="")
                
                # Clear login fields
                self.login_username.delete(0, tk.END)
                self.login_password.delete(0, tk.END)
                
                # Show chat frame
                self.show_frame("chat")
                self.running = True
                
                # Start thread for receiving messages
                threading.Thread(target=self.receive_messages, daemon=True).start()
                
                self.display_message("System", "You are now connected to the chat server.")
                
            except Exception as e:
                self.login_status.config(text=response if response else "Invalid server response")
                self.socket.close()
                self.socket = None
                
        except socket.timeout:
            self.login_status.config(text="Connection timed out")
        except Exception as e:
            self.login_status.config(text=f"Connection error: {str(e)}")
            if self.socket:
                self.socket.close()
                self.socket = None
        finally:
            # Re-enable buttons
            for widget in self.login_frame.winfo_children():
                if isinstance(widget, ttk.Button):
                    widget.config(state=tk.NORMAL)
    
    def show_message_menu(self, event):
        """Show the right-click menu for messages with visual selection"""
        try:
            # Remove previous highlight if exists
            if self.last_highlighted:
                start, end = self.last_highlighted
                self.chat_display.tag_remove("highlight", start, end)
            
            # Get the clicked message
            index = self.chat_display.index(f"@{event.x},{event.y}")
            line_start = index.split(".")[0] + ".0"
            line_end = index.split(".")[0] + ".end"
            
            # Highlight the selected message
            self.chat_display.tag_config("highlight", background="#e6e6e6")
            self.chat_display.tag_add("highlight", line_start, line_end)
            self.last_highlighted = (line_start, line_end)
            
            # Get the message content
            message_content = self.chat_display.get(line_start, line_end)
            
            # Find message ID in history
            for msg_id, (sender, msg, _) in self.message_history.items():
                if f"{sender}: {msg}" in message_content:
                    # Only allow editing your own messages
                    if sender == self.username:
                        self.currently_selected = msg_id
                        self.message_menu.post(event.x_root, event.y_root)
                    break
        except Exception as e:
            print(f"Error showing menu: {e}")

    
    def start_editing_message(self):
        """Start editing the selected message"""
        if not self.currently_selected:
            return
        
        msg_id = self.currently_selected
        if msg_id in self.message_history:
            sender, message, _ = self.message_history[msg_id]
            if sender == self.username:  # Only allow editing your own messages
                self.currently_editing = msg_id
                self.message_entry.delete(0, tk.END)
                self.message_entry.insert(0, message)
                self.show_edit_controls()
    
    def show_edit_controls(self):
        """Show the edit controls instead of send button"""
        self.send_btn.pack_forget()
        self.edit_controls.pack(side=tk.LEFT)
    
    def show_normal_send_controls(self):
        """Show the normal send controls"""
        self.edit_controls.pack_forget()
        self.send_btn.pack(side=tk.LEFT)
        self.currently_editing = None
    
    def save_edited_message(self):
        """Save the edited message and send to server"""
        if not self.currently_editing:
            return
        
        new_message = self.message_entry.get().strip()
        if not new_message:
            messagebox.showwarning("Warning", "Message cannot be empty")
            return
        
        msg_id = self.currently_editing
        if msg_id in self.message_history:
            # Update local history
            sender, _, timestamp = self.message_history[msg_id]
            self.message_history[msg_id] = (sender, new_message, timestamp)
            
            # Send edit command to server
            try:
                command = f"/edit {msg_id}:{new_message}"
                encrypted_msg = self.encrypt_message(command, self.session_key)
                self.socket.sendall(encrypted_msg)
                
                # Clear and reset UI
                self.message_entry.delete(0, tk.END)
                self.show_normal_send_controls()
                
                # Update display
                self.update_message_display()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to edit message: {str(e)}")

    def cancel_editing(self):
        """Cancel the editing process"""
        self.message_entry.delete(0, tk.END)
        self.show_normal_send_controls()
    
    def update_message_display(self):
        """Update the chat display with current message history (hiding UUIDs)"""
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        
        # Sort messages by timestamp
        sorted_messages = sorted(self.message_history.items(), 
                            key=lambda x: x[1][2])  # x[1][2] is the timestamp
        
        for msg_id, (sender, message, _) in sorted_messages:
            # Configure tags for different senders
            if sender == self.username:
                tag = "you"
                color = "blue"
            elif sender == "System":
                tag = "system"
                color = "red"
            else:
                tag = "other"
                color = "green"
            
            # Create tag if it doesn't exist
            if tag not in self.chat_display.tag_names():
                self.chat_display.tag_config(tag, foreground=color)
            
            # Insert message (without UUID)
            self.chat_display.insert(tk.END, f"{sender}: ", tag)
            self.chat_display.insert(tk.END, f"{message}\n")
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)  # Auto-scroll to bottom
        
    def pad_message(self, message):
        """Pad message for AES encryption (PKCS7)"""
        pad_length = AES_BLOCK_SIZE - (len(message) % AES_BLOCK_SIZE)
        return message + bytes([pad_length] * pad_length)
    
    def unpad_message(self, padded_message):
        """Unpad message after AES decryption (PKCS7)"""
        pad_length = padded_message[-1]
        return padded_message[:-pad_length]
    
    def encrypt_message(self, message, key):
        """Encrypt message with AES-256 in CBC mode"""
        iv = Random.new().read(AES_BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = self.pad_message(message.encode('utf-8'))
        ciphertext = cipher.encrypt(padded_message)
        return iv + ciphertext
    
    def decrypt_message(self, encrypted_message, key):
        """Decrypt message with AES-256 in CBC mode"""
        iv = encrypted_message[:AES_BLOCK_SIZE]
        ciphertext = encrypted_message[AES_BLOCK_SIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(ciphertext)
        return self.unpad_message(padded_message).decode('utf-8')
    
    def send_message(self):
        """Send a message to the server"""
        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            msg_id = str(uuid4())
            timestamp = time.time()

            # Add to local history
            self.message_history[msg_id] = (self.username, message, timestamp)

            # Format: UUID:sender:message
            full_message = f"{msg_id}:{self.username}:{message}"
            encrypted_msg = self.encrypt_message(full_message, self.session_key)
            self.socket.sendall(encrypted_msg)

            self.message_entry.delete(0, tk.END)
            self.update_message_display()

        except Exception as e:
            self.display_message("System", f"Error sending message: {str(e)}")
            self.disconnect()
            
    def parse_message_with_uuid(self, message):
        """
        Parse message in format sender:message or UUID:sender:message.
        Returns (sender, message) without UUID.
        """
        if ":" in message and message.count(":") >= 2:
            try:
                _, sender, actual_message = message.split(":", 2)
                return sender.strip(), actual_message.strip()
            except ValueError:
                pass
        elif ":" in message:
            try:
                sender, actual_message = message.split(":", 1)
                return sender.strip(), actual_message.strip()
            except ValueError:
                pass
        return "System", message.strip()

    def display_message(self, sender, message):
        """Append a single message to message history and refresh chat display"""
        # Find an unused UUID (for system messages, or fallback)
        msg_id = str(uuid4())
        timestamp = time.time()
        self.message_history[msg_id] = (sender, message, timestamp)
        self.update_message_display()
    
    def receive_messages(self):
        """Receive and process messages from server"""
        while self.running:
            try:
                encrypted_msg = self.socket.recv(BUFFER_SIZE)
                if not encrypted_msg:
                    break

                decrypted_msg = self.decrypt_message(encrypted_msg, self.session_key)

                # Edits
                if decrypted_msg.startswith("/edit "):
                    _, content = decrypted_msg.split(" ", 1)
                    msg_id, new_msg = content.split(":", 1)
                    if msg_id in self.message_history:
                        sender, _, timestamp = self.message_history[msg_id]
                        self.message_history[msg_id] = (sender, new_msg.strip(), timestamp)
                        self.root.after(0, self.update_message_display)
                    continue

                # Regular message
                if decrypted_msg.count(":") >= 2:
                    try:
                        msg_id, rest = decrypted_msg.split(":", 1)
                        sender, message = self.parse_message_with_uuid(rest)
                        self.message_history[msg_id.strip()] = (sender, message, time.time())
                        self.root.after(0, self.update_message_display)
                    except ValueError:
                        self.root.after(0, self.display_message, "System", decrypted_msg)
                else:
                    self.root.after(0, self.display_message, "System", decrypted_msg)

            except Exception as e:
                if self.running:
                    self.root.after(0, self.display_message, "System", f"Error: {str(e)}")
                break

        self.root.after(0, self.disconnect)
    
    def disconnect(self):
        """Disconnect from the server and return to welcome screen"""
        if not self.running:
            return  # Already disconnected
        
        self.running = False
        
        try:
            if self.socket:
                self.socket.close()
        except:
            pass
        
        # Clear chat display but preserve state
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state='disabled')
        
        # Reset state
        self.username = None
        self.session_key = None
        self.socket = None
        self.message_history = {}
        self.currently_selected = None
        self.currently_editing = None
        
        # Return to welcome screen
        self.show_frame("welcome")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatGUI(root)
    root.mainloop()