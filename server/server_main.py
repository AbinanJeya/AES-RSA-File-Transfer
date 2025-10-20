import socket
import threading
import os
from shared.constants import HOST, PORT, BUFFER_SIZE
from server.encryption import aes_decrypt, decrypt_aes_key, generate_rsa_keys, aes_encrypt, encrypt_aes_key
from server.user_manager import authenticate
from cryptography.hazmat.primitives import serialization

DATA_FOLDER = "data"
os.makedirs(DATA_FOLDER, exist_ok=True)

private_key, public_key = generate_rsa_keys()

def recv_exact(conn, size):
    """Receive exactly size bytes from the connection"""
    data = b""
    while len(data) < size:
        chunk = conn.recv(min(size - len(data), BUFFER_SIZE))
        if not chunk:
            raise ConnectionError("Connection lost")
        data += chunk
    return data

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    
    # Send public key to client first
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.send(public_key_pem)
    
    conn.send(b"Username: ")
    username = conn.recv(BUFFER_SIZE).decode().strip()
    conn.send(b"Password: ")
    password = conn.recv(BUFFER_SIZE).decode().strip()

    if not authenticate(username, password):
        conn.send(b"Authentication failed.\n")
        conn.close()
        return

    conn.send(b"Authentication successful.\n")
    
    while True:
        try:
            command = conn.recv(BUFFER_SIZE).decode().strip().lower()
            print(f"[COMMAND] {addr} sent: {command}")

            if command == "upload":
                # Acknowledge command receipt
                conn.send(b"Ready for upload\n")
                
                # Receive filename
                filename = conn.recv(BUFFER_SIZE).decode().strip()
                print(f"[UPLOAD] Receiving file: {filename}")
                
                # Receive encrypted AES key
                encrypted_aes_key = recv_exact(conn, 256)
                print(f"[UPLOAD] Received AES key: {len(encrypted_aes_key)} bytes")
                
                # Receive file size
                filesize_data = b""
                while True:
                    chunk = conn.recv(1)
                    if chunk == b"\n" or not chunk:
                        break
                    filesize_data += chunk
                
                if not filesize_data:
                    raise ValueError("No file size received")
                
                filesize = int(filesize_data.decode().strip())
                print(f"[UPLOAD] File size: {filesize} bytes")
                
                # Receive file data
                data = recv_exact(conn, filesize)
                print(f"[UPLOAD] Received data: {len(data)} bytes")
                
                # Decrypt and save file
                aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
                file_data = aes_decrypt(data, aes_key)
                
                with open(os.path.join(DATA_FOLDER, filename), "wb") as f:
                    f.write(file_data)
                
                print(f"[UPLOAD] File {filename} saved successfully")
                conn.send(b"Upload complete.\n")

            elif command == "download":
                # Send filename prompt
                conn.send(b"Enter filename to download: ")
                filename = conn.recv(BUFFER_SIZE).decode().strip()
                filepath = os.path.join(DATA_FOLDER, filename)
                
                if not os.path.exists(filepath):
                    conn.send(b"File not found.\n")
                    continue
                
                print(f"[DOWNLOAD] Sending file: {filename}")
                
                # Read and encrypt file
                with open(filepath, "rb") as f:
                    file_data = f.read()
                
                aes_key = os.urandom(32)
                encrypted_data = aes_encrypt(file_data, aes_key)
                encrypted_aes_key = encrypt_aes_key(aes_key, public_key)
                
                # Send encrypted data
                conn.send(encrypted_aes_key)
                filesize_msg = str(len(encrypted_data)) + "\n"
                conn.send(filesize_msg.encode())
                conn.sendall(encrypted_data)
                
                print(f"[DOWNLOAD] File {filename} sent successfully")
                
                # Wait for client acknowledgment
                try:
                    ack = conn.recv(BUFFER_SIZE).decode()
                    print(f"[DOWNLOAD] Client acknowledgment: {ack}")
                except:
                    pass

            elif command == "list":
                # Acknowledge command receipt
                conn.send(b"Ready for list\n")
                
                files = os.listdir(DATA_FOLDER)
                if not files:
                    file_list = "No files available.\n"
                else:
                    file_list = "Available files:\n" + "\n".join(f" - {f}" for f in files) + "\n"
                conn.send(file_list.encode())
                print(f"[LIST] Sent file list: {len(files)} files")

            elif command == "exit":
                conn.send(b"Goodbye!\n")
                conn.close()
                break

            else:
                conn.send(b"Invalid command.\n")

        except Exception as e:
            print(f"[ERROR] Handling command failed: {e}")
            try:
                conn.send(f"Error: {str(e)}\n".encode())
            except:
                pass
            break

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[LISTENING] Server running on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()