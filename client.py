import socket

# For File Encryption
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from secret import key
import os

SALT_SIZE = 12


def encryption(file_path: str) -> None:
    cipher = ChaCha20Poly1305(key)
    plaintext = ""
    with open(file_path, "rb") as file:
        plaintext = file.read()
    salt = os.urandom(SALT_SIZE)
    print(salt)
    ciphertext = cipher.encrypt(salt, plaintext, None)
    print(ciphertext)
    with open(file_path + ".enc", "wb") as encrypted_file:
        encrypted_file.write(salt + ciphertext)


def decryption(file_path: str) -> None:
    cipher = ChaCha20Poly1305(key)
    ciphertext = ""
    with open(file_path + ".enc", "rb") as encrypted_file:
        data = encrypted_file.read()
        salt = data[:SALT_SIZE]
        ciphertext = data[SALT_SIZE:]
    print(salt)
    print(ciphertext)
    plaintext = cipher.decrypt(salt, ciphertext, None)

    with open(file_path, "wb") as file:
        file.write(plaintext)


def send_command(command):
    client_socket.send(command.encode())
    response = client_socket.recv(1024).decode()
    print(response)


# ls & cd only for navigation
def display_help():
    print("Available commands:")
    print("ls - Lists all files in the current directory")
    print("cd <directory> - Changes the current directory")
    print("uf <filename> - Copies the file from 'Files' to 'Uploads'")
    print("qp - Ends the connection to the server")
    print("-help - Shows this help")


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 12345

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((host, port))
        while True:
            command = input(">>> ")
            cmd_parts = command.split(" ", 1)

            if command == "-help":
                display_help()
                continue
            elif cmd_parts[0] == "uf":
                file_name = "Files/" + (cmd_parts[1] if len(cmd_parts) > 1 else "")
                encryption(file_name)
            elif cmd_parts[0] == "df":
                send_command(command)
                file_name = "Files/" + (cmd_parts[1] if len(cmd_parts) > 1 else "")
                decryption(file_name)
                continue
            elif command == "qp":
                break
            send_command(command)
    except socket.timeout as e:
        print(f"Error connecting to the server: {e}")
        exit()
    finally:
        client_socket.close()
        print("Connection closed")
        exit()
