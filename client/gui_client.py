import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import socket
import os
import threading
import hashlib
import json
from shared.constants import HOST, PORT, BUFFER_SIZE
from server.encryption import encrypt_aes_key, aes_encrypt
from cryptography.hazmat.primitives import serialization

USERS_FILE = "users.json"

class SecureShareGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureShare - Secure File Sharing")
        self.root.geometry("800x600")
        
        # Client state
        self.client_socket = None
        self.public_key = None
        self.connected = False
        self.authenticated = False
        self.available_files = []
        
        self.setup_gui()
        
    def setup_gui(self):
        # Create main frames
        self.login_frame = ttk.Frame(self.root, padding="10")
        self.main_frame = ttk.Frame(self.root, padding="10")
        
        self.setup_login_frame()
        self.setup_main_frame()
        
        # Show login frame initially
        self.show_login_frame()
        
    def setup_login_frame(self):
        # Connection section
        conn_frame = ttk.LabelFrame(self.login_frame, text="Connection", padding="10")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(conn_frame, text="Host:").grid(row=0, column=0, sticky=tk.W)
        self.host_entry = ttk.Entry(conn_frame, width=20)
        self.host_entry.insert(0, HOST)
        self.host_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(20,0))
        self.port_entry = ttk.Entry(conn_frame, width=10)
        self.port_entry.insert(0, str(PORT))
        self.port_entry.grid(row=0, column=3, padx=5)
        
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.connect_to_server)
        self.connect_btn.grid(row=0, column=4, padx=10)
        
        # Login/Register section
        auth_frame = ttk.LabelFrame(self.login_frame, text="Authentication", padding="10")
        auth_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Username
        ttk.Label(auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_entry = ttk.Entry(auth_frame, width=20)
        self.username_entry.grid(row=0, column=1, padx=5)
        
        # Password
        ttk.Label(auth_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(auth_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Buttons frame
        button_frame = ttk.Frame(auth_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.login_btn = ttk.Button(button_frame, text="Login", command=self.login, state=tk.DISABLED)
        self.login_btn.grid(row=0, column=0, padx=5)
        
        self.register_btn = ttk.Button(button_frame, text="Register", command=self.register_user)
        self.register_btn.grid(row=0, column=1, padx=5)
        
        # Status section
        status_frame = ttk.Frame(self.login_frame, padding="10")
        status_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        self.status_text = scrolledtext.ScrolledText(status_frame, height=8, width=70, state=tk.DISABLED)
        self.status_text.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
    def setup_main_frame(self):
        # File operations frame
        files_frame = ttk.LabelFrame(self.main_frame, text="File Operations", padding="10")
        files_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Upload section
        upload_frame = ttk.Frame(files_frame)
        upload_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(upload_frame, text="Select File to Upload", 
                  command=self.select_upload_file).grid(row=0, column=0, padx=5)
        self.upload_path_label = ttk.Label(upload_frame, text="No file selected")
        self.upload_path_label.grid(row=0, column=1, padx=5)
        ttk.Button(upload_frame, text="Upload", 
                  command=self.upload_file).grid(row=0, column=2, padx=5)
        
        # Download section
        download_frame = ttk.Frame(files_frame)
        download_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(download_frame, text="Select file to download:").grid(row=0, column=0, sticky=tk.W)
        self.file_listbox = tk.Listbox(download_frame, height=6, width=40)
        self.file_listbox.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(download_frame, text="Refresh List", 
                  command=self.refresh_file_list).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(download_frame, text="Download Selected", 
                  command=self.download_selected_file).grid(row=2, column=1, padx=5, pady=5)
        
        # Status and log frame
        log_frame = ttk.LabelFrame(self.main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=70, state=tk.DISABLED)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Control buttons
        control_frame = ttk.Frame(self.main_frame)
        control_frame.grid(row=2, column=0, pady=10)
        
        ttk.Button(control_frame, text="Disconnect", 
                  command=self.disconnect).grid(row=0, column=0, padx=5)
        
        # Configure grid weights
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        
    def show_login_frame(self):
        self.main_frame.grid_forget()
        self.login_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
    def show_main_frame(self):
        self.login_frame.grid_forget()
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.refresh_file_list()
        
    def log_message(self, message, is_error=False):
        """Add message to log with timestamp"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        tag = "ERROR" if is_error else "INFO"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {tag}: {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def status_message(self, message):
        """Add message to status area"""
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, message + "\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)
        
    def load_users(self):
        """Load users from JSON file"""
        if not os.path.exists(USERS_FILE):
            return {}
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            self.log_message(f"Error loading users: {e}", is_error=True)
            return {}
    
    def save_users(self, users):
        """Save users to JSON file"""
        try:
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=4)
            return True
        except Exception as e:
            self.log_message(f"Error saving users: {e}", is_error=True)
            return False
    
    def register_user(self):
        """Register a new user locally"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showwarning("Registration Error", "Please enter both username and password")
            return
        
        if len(username) < 3:
            messagebox.showwarning("Registration Error", "Username must be at least 3 characters long")
            return
        
        if len(password) < 4:
            messagebox.showwarning("Registration Error", "Password must be at least 4 characters long")
            return
        
        users = self.load_users()
        
        if username in users:
            messagebox.showerror("Registration Error", f"User '{username}' already exists!")
            return
        
        # Hash the password and save the user
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        users[username] = hashed_password
        
        if self.save_users(users):
            messagebox.showinfo("Registration Successful", f"User '{username}' registered successfully!\nYou can now login.")
            self.log_message(f"New user registered: {username}")
            # Clear password field for security
            self.password_entry.delete(0, tk.END)
        else:
            messagebox.showerror("Registration Error", "Failed to save user registration")
        
    def connect_to_server(self):
        try:
            host = self.host_entry.get()
            port = int(self.port_entry.get())
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            
            # Get server's public key
            public_key_pem = self.client_socket.recv(BUFFER_SIZE)
            self.public_key = serialization.load_pem_public_key(public_key_pem)
            
            self.connected = True
            self.login_btn.config(state=tk.NORMAL)
            self.status_message("✓ Connected to server successfully!")
            self.log_message("Connected to server and received public key")
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            self.log_message(f"Connection failed: {str(e)}", is_error=True)
            
    def login(self):
        try:
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            
            if not username or not password:
                messagebox.showwarning("Input Error", "Please enter both username and password")
                return
            
            # Receive username prompt and send username
            self.client_socket.recv(BUFFER_SIZE)  # "Username: " prompt
            self.client_socket.send(username.encode())
            
            # Receive password prompt and send password
            self.client_socket.recv(BUFFER_SIZE)  # "Password: " prompt
            self.client_socket.send(password.encode())
            
            # Check authentication result
            auth_result = self.client_socket.recv(BUFFER_SIZE).decode()
            
            if "successful" in auth_result:
                self.authenticated = True
                self.status_message("✓ Authentication successful!")
                self.log_message(f"User '{username}' logged in successfully")
                self.show_main_frame()
            else:
                messagebox.showerror("Authentication Failed", "Invalid username or password")
                self.log_message("Authentication failed", is_error=True)
                
        except Exception as e:
            messagebox.showerror("Login Error", f"Login failed: {str(e)}")
            self.log_message(f"Login error: {str(e)}", is_error=True)
            
    def select_upload_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to upload",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.upload_path_label.config(text=os.path.basename(filename))
            self.upload_file_path = filename
            self.log_message(f"Selected file for upload: {os.path.basename(filename)}")
            
    def upload_file(self):
        if not hasattr(self, 'upload_file_path') or not self.upload_file_path:
            messagebox.showwarning("Upload Error", "Please select a file first")
            return
            
        try:
            # Send upload command
            self.client_socket.send(b"upload")
            
            # Wait for command prompt acknowledgment
            response = self.client_socket.recv(BUFFER_SIZE).decode()
            self.log_message(f"Server ready for upload: {response}")
            
            # Use the existing send_file logic
            self.send_file_gui(self.upload_file_path)
            
            # Get server response
            response = self.client_socket.recv(BUFFER_SIZE).decode()
            self.log_message(f"Upload response: {response}")
            
            if "complete" in response.lower() or "success" in response.lower():
                messagebox.showinfo("Upload", "File uploaded successfully!")
            else:
                messagebox.showwarning("Upload", response)
            
            # Refresh file list
            self.refresh_file_list()
            
        except Exception as e:
            messagebox.showerror("Upload Error", f"Upload failed: {str(e)}")
            self.log_message(f"Upload error: {str(e)}", is_error=True)
            
    def send_file_gui(self, filename):
        """GUI version of send_file function"""
        with open(filename, "rb") as f:
            data = f.read()

        aes_key = os.urandom(32)
        encrypted_data = aes_encrypt(data, aes_key)
        encrypted_aes_key = encrypt_aes_key(aes_key, self.public_key)

        filename_only = os.path.basename(filename)
        
        self.log_message(f"Uploading: {filename_only} ({len(data)} bytes)")
        
        # Send filename
        self.client_socket.send(filename_only.encode())
        
        # Send encrypted AES key
        self.client_socket.send(encrypted_aes_key)
        
        # Send file size
        filesize_msg = str(len(encrypted_data)) + "\n"
        self.client_socket.send(filesize_msg.encode())
        
        # Send encrypted data
        self.client_socket.sendall(encrypted_data)
        
        self.log_message("File data sent successfully")
        
    def refresh_file_list(self):
        try:
            # Send list command
            self.client_socket.send(b"list")
            
            # Wait for command prompt acknowledgment  
            response = self.client_socket.recv(BUFFER_SIZE).decode()
            self.log_message(f"Server ready for list: {response}")
            
            # Receive file list
            file_list_data = self.client_socket.recv(BUFFER_SIZE).decode()
            
            # Update listbox
            self.file_listbox.delete(0, tk.END)
            files = []
            
            # Parse file list
            for line in file_list_data.split('\n'):
                line = line.strip()
                if line and not line.startswith("Available files") and line != "No files available":
                    # Remove bullet points if present
                    clean_file = line.lstrip('- ').strip()
                    if clean_file:
                        files.append(clean_file)
                        self.file_listbox.insert(tk.END, clean_file)
                    
            self.available_files = files
            self.log_message(f"Refreshed file list: {len(files)} files")
            
        except Exception as e:
            messagebox.showerror("Refresh Error", f"Failed to refresh file list: {str(e)}")
            self.log_message(f"Refresh error: {str(e)}", is_error=True)
            
    def download_selected_file(self):
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showwarning("Download Error", "Please select a file to download")
            return
            
        filename = self.file_listbox.get(selection[0])
        
        try:
            # Send download command
            self.client_socket.send(b"download")
            
            # Wait for filename prompt
            prompt = self.client_socket.recv(BUFFER_SIZE).decode()
            self.log_message(f"Server prompt: {prompt}")
            
            # Send filename
            self.client_socket.send(filename.encode())
            
            # Download the file using the robust method
            success = self.robust_download(filename)
            
            if success:
                messagebox.showinfo("Download", f"File '{filename}' downloaded successfully!")
                self.log_message(f"Downloaded: {filename}")
            else:
                messagebox.showerror("Download Error", f"Failed to download {filename}")
            
        except Exception as e:
            messagebox.showerror("Download Error", f"Download failed: {str(e)}")
            self.log_message(f"Download error: {str(e)}", is_error=True)

    def robust_download(self, filename):
        """Robust download method that handles the protocol properly"""
        try:
            download_folder = "downloads"
            os.makedirs(download_folder, exist_ok=True)
            
            # Step 1: Check for immediate error response
            self.client_socket.settimeout(3.0)
            try:
                initial_response = self.client_socket.recv(BUFFER_SIZE)
                # Try to decode as error message
                try:
                    error_msg = initial_response.decode()
                    if "not found" in error_msg.lower() or "error" in error_msg.lower():
                        self.log_message(f"Server error: {error_msg}", is_error=True)
                        return False
                except UnicodeDecodeError:
                    # It's binary data, proceed with download
                    pass
            except socket.timeout:
                # No immediate response, might be processing
                self.log_message("No immediate response, waiting for data...")
                initial_response = b""
            finally:
                self.client_socket.settimeout(None)
            
            # Step 2: Receive all download data
            all_data = initial_response
            self.client_socket.settimeout(2.0)
            
            try:
                while True:
                    chunk = self.client_socket.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    all_data += chunk
            except socket.timeout:
                # Expected - download complete
                pass
            finally:
                self.client_socket.settimeout(None)
            
            if len(all_data) == 0:
                self.log_message("No data received for download", is_error=True)
                return False
            
            self.log_message(f"Received {len(all_data)} bytes total for download")
            
            # Step 3: Parse the download data
            # Format should be: [256-byte AES key] + [filesize\n] + [encrypted data]
            
            if len(all_data) < 256:
                self.log_message(f"Insufficient data for AES key: {len(all_data)} bytes", is_error=True)
                return False
            
            # Extract encrypted AES key (first 256 bytes)
            encrypted_aes_key = all_data[:256]
            remaining_data = all_data[256:]
            
            # Find the newline that separates filesize from encrypted data
            newline_pos = remaining_data.find(b'\n')
            if newline_pos == -1:
                self.log_message("No filesize delimiter found", is_error=True)
                return False
            
            # Extract filesize
            filesize_str = remaining_data[:newline_pos].decode().strip()
            try:
                filesize = int(filesize_str)
            except ValueError:
                self.log_message(f"Invalid filesize: {filesize_str}", is_error=True)
                return False
            
            # Extract encrypted data
            encrypted_data = remaining_data[newline_pos + 1:]
            
            # Verify we have all the encrypted data
            if len(encrypted_data) < filesize:
                self.log_message(f"Incomplete data: got {len(encrypted_data)} of {filesize} bytes", is_error=True)
                # Try to get remaining data
                remaining_bytes = filesize - len(encrypted_data)
                try:
                    additional_data = self.recv_exact(remaining_bytes)
                    encrypted_data += additional_data
                    self.log_message(f"Received additional {len(additional_data)} bytes")
                except Exception as e:
                    self.log_message(f"Failed to get remaining data: {e}", is_error=True)
                    return False
            
            # Step 4: Save the file
            download_path = os.path.join(download_folder, f"encrypted_{filename}")
            with open(download_path, "wb") as f:
                f.write(encrypted_aes_key)
                f.write(filesize_str.encode() + b"\n")
                f.write(encrypted_data)
            
            self.log_message(f"Successfully saved encrypted file: {download_path} ({len(encrypted_data)} bytes)")
            
            # Step 5: Send acknowledgment to server
            self.client_socket.send(b"Download received\n")
            
            return True
            
        except Exception as e:
            self.log_message(f"Robust download error: {str(e)}", is_error=True)
            return False

    def recv_exact(self, size):
        """Receive exactly size bytes from the connection"""
        data = b""
        while len(data) < size:
            chunk = self.client_socket.recv(min(size - len(data), BUFFER_SIZE))
            if not chunk:
                raise ConnectionError("Connection lost")
            data += chunk
        return data
        
    def disconnect(self):
        try:
            if self.client_socket:
                self.client_socket.send(b"exit")
                self.client_socket.close()
        except:
            pass
            
        self.connected = False
        self.authenticated = False
        self.client_socket = None
        self.public_key = None
        
        self.log_message("Disconnected from server")
        self.show_login_frame()
        
        # Clear login fields
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.upload_path_label.config(text="No file selected")
        if hasattr(self, 'upload_file_path'):
            del self.upload_file_path

def main():
    root = tk.Tk()
    app = SecureShareGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()