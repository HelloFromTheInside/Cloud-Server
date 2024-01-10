import socket

# For File Encryption
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from secret import key
import os

SALT_SIZE = 12


def readfile(file_path: str):
    try:
        with open(file_path, "rb") as file:
            text = file.read()
    except FileNotFoundError:
        print("The file does not exist.")
        return 1
    except Exception as e:
        print(f"An error occurred: {e}")
        return 1
    return text


def write_file(file_path: str, text: bytes) -> int:
    try:
        with open(file_path, "wb") as file:
            file.write(text)
    except Exception as e:
        print(f"An error occurred: {e}")
        return 1
    return 0


def cryption(file_path: str, encrypt: bool) -> int:
    cipher = ChaCha20Poly1305(key)
    if (text := readfile(file_path + ".enc" * (not encrypt))) == 1:
        return 1
    if (text := (encryption if encrypt else decryption)(cipher, text)) == 1:
        return 2
    return write_file(file_path + ".enc" * encrypt, text)


def encryption(cipher: ChaCha20Poly1305, plaintext: bytes) -> bytes:
    salt = os.urandom(SALT_SIZE)
    ciphertext = cipher.encrypt(salt, plaintext, None)
    return salt + ciphertext


def decryption(cipher: ChaCha20Poly1305, data: bytes):
    salt = data[:SALT_SIZE]
    ciphertext = data[SALT_SIZE:]
    try:
        plaintext = cipher.decrypt(salt, ciphertext, None)
    except InvalidTag:
        return 1
    return plaintext


def send_command(command) -> None:
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
                if cryption(file_name, True):
                    continue
            elif cmd_parts[0] == "df":
                send_command(command)
                file_name = "Files/" + (cmd_parts[1] if len(cmd_parts) > 1 else "")
                if cryption(file_name, False):
                    print("File is corrupted, please continue with precaution!")
                continue
            send_command(command)
            if command == "qp":
                break
    except socket.timeout as e:
        print(f"Error connecting to the server: {e}")
    finally:
        client_socket.close()
        print("Connection closed")
        exit()
