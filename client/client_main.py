import socket
import os
from shared.constants import HOST, PORT, BUFFER_SIZE
from server.encryption import encrypt_aes_key, aes_encrypt, aes_decrypt, decrypt_aes_key
from cryptography.hazmat.primitives import serialization

# Create a downloads folder
DOWNLOAD_FOLDER = "downloads"
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

def get_server_public_key(client_socket):
    """Receive the server's public key"""
    public_key_pem = client_socket.recv(BUFFER_SIZE)
    public_key = serialization.load_pem_public_key(public_key_pem)
    return public_key

def recv_exact(conn, size):
    """Receive exactly size bytes from the connection"""
    data = b""
    while len(data) < size:
        chunk = conn.recv(min(size - len(data), BUFFER_SIZE))
        if not chunk:
            raise ConnectionError("Connection lost")
        data += chunk
    return data

def send_file(filename, client_socket, public_key):
    try:
        with open(filename, "rb") as f:
            data = f.read()

        # Generate AES key and encrypt file
        aes_key = os.urandom(32)
        encrypted_data = aes_encrypt(data, aes_key)
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

        # Extract just the filename from the path
        filename_only = os.path.basename(filename)
        
        print(f"[UPLOAD] Sending file: {filename_only}")
        print(f"[UPLOAD] File size: {len(data)} bytes, Encrypted size: {len(encrypted_data)} bytes")
        
        # Send filename
        client_socket.send(filename_only.encode())
        
        # Small delay to ensure separation between messages
        import time
        time.sleep(0.1)
        
        # Send encrypted AES key (fixed size)
        client_socket.send(encrypted_aes_key)
        print(f"[UPLOAD] Sent AES key: {len(encrypted_aes_key)} bytes")
        
        # Send file size followed by newline
        filesize_msg = str(len(encrypted_data)) + "\n"
        client_socket.send(filesize_msg.encode())
        
        # Send encrypted data
        client_socket.sendall(encrypted_data)
        print(f"[UPLOAD] File data sent successfully")
        
    except Exception as e:
        print(f"[ERROR] Failed to send file: {e}")
        raise

def download_file(client_socket, filename):
    try:
        # Receive encrypted AES key
        encrypted_aes_key = recv_exact(client_socket, 256)
        
        # Receive file size (until newline)
        filesize_data = b""
        while True:
            chunk = client_socket.recv(1)
            if chunk == b"\n" or not chunk:
                break
            filesize_data += chunk
        
        if not filesize_data:
            raise ValueError("No file size received")
        
        filesize = int(filesize_data.decode().strip())
        
        # Receive encrypted data
        encrypted_data = recv_exact(client_socket, filesize)
        
        print(f"[DOWNLOAD] Received file data: {filesize} bytes")
        
        # Save the encrypted file to downloads folder
        download_path = os.path.join(DOWNLOAD_FOLDER, f"encrypted_{filename}")
        with open(download_path, "wb") as f:
            # Save the encrypted AES key and encrypted data together
            f.write(encrypted_aes_key)  # First 256 bytes: encrypted AES key
            f.write(filesize_data + b"\n")  # Then file size info
            f.write(encrypted_data)  # Then the encrypted file data
        
        print(f"[DOWNLOAD] Encrypted file saved to: {download_path}")
        print("[INFO] Note: File is encrypted. To decrypt, you would need client RSA keys.")
        
        # Send acknowledgment
        client_socket.send(b"Download received\n")
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Download failed: {e}")
        return False

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    
    # Get server's public key first
    public_key = get_server_public_key(client)
    print("[INFO] Received server public key")
    
    print(client.recv(BUFFER_SIZE).decode(), end="")
    username = input()
    client.send(username.encode())
    
    print(client.recv(BUFFER_SIZE).decode(), end="")
    password = input()
    client.send(password.encode())
    
    auth_result = client.recv(BUFFER_SIZE).decode()
    print(auth_result, end="")
    
    if "failed" in auth_result:
        client.close()
        return

    while True:
        command_prompt = client.recv(BUFFER_SIZE).decode()
        print(command_prompt, end="")
        cmd = input().strip().lower()
        client.send(cmd.encode())
        
        if cmd == "exit":
            print(client.recv(BUFFER_SIZE).decode(), end="")
            break
        elif cmd == "upload":
            filename = input("Enter file path: ").strip()
            if os.path.exists(filename):
                try:
                    send_file(filename, client, public_key)
                    response = client.recv(BUFFER_SIZE).decode()
                    print(response, end="")
                except Exception as e:
                    print(f"Upload error: {e}")
            else:
                print("File not found!")
        elif cmd == "download":
            filename = input("Enter filename to download: ").strip()
            client.send(filename.encode())
            response = client.recv(BUFFER_SIZE).decode()
            if "not found" in response:
                print(response, end="")
            else:
                # Download process
                if download_file(client, filename):
                    print("Download completed successfully")
        elif cmd == "list":
            file_list = client.recv(BUFFER_SIZE).decode()
            print(file_list, end="")

    client.close()

if __name__ == "__main__":
    main()