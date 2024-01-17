import socket
from crypto import (
    filecryption,
    handle_login_user,
    encryption,
    decryption,
    create_new_cipher,
)


def send_command(key: bytes, salt: bytes, command: str) -> tuple[bytes, bytes]:
    key, salt, cipher = create_new_cipher(key, salt)
    enc_command = encryption(cipher, command.encode())
    client_socket.send(salt + enc_command)
    data = client_socket.recv(1024)
    old_salt = data[:24]
    enc_response = data[24:]
    key, salt, cipher = create_new_cipher(key, old_salt)
    if not (response := decryption(cipher, enc_response)):
        print("Message is corrupted, please continue with precaution!")
        return key, salt
    print(response.decode())
    return key, salt


# ls & cd only for navigation
def display_help() -> None:
    print("Available commands:")
    print("ls - Lists all files in the current directory")
    print("uf <filename> - Copies the file from 'Files' to 'Uploads'")
    print("df <filename> - Copies the file from 'Uploads' to 'Files'")
    print("rm <filename> - Deletes a file on the server")
    print("qp - Ends the connection to the server")
    print("-help - Shows this help")


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 12345
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    try:
        salt = b""
        if not (data := handle_login_user(client_socket)):
            raise Exception("Login has failed!")
        key = data[0]
        if not data[1]:
            raise Exception("Key for File en/decryption was tempered with!")
        file_key: bytes = data[1]
        while True:
            try:
                command = input(">>> ")
            except KeyboardInterrupt:
                key, salt = send_command(key, salt, "qp")
                break
            cmd_parts = command.split(" ", 1)

            if command == "-help":
                display_help()
                continue
            elif cmd_parts[0] == "uf":
                file_name = "Files/" + (cmd_parts[1] if len(cmd_parts) > 1 else "")
                if filecryption(file_name, True, file_key):
                    continue
            elif cmd_parts[0] == "df":
                key, salt = send_command(key, salt, command)
                file_name = "Files/" + (cmd_parts[1] if len(cmd_parts) > 1 else "")
                if filecryption(file_name, False, file_key) == 2:
                    print("File is corrupted, please continue with precaution!")
                continue
            key, salt = send_command(key, salt, command)
            if command == "qp":
                break
    except socket.timeout as e:
        print(f"Error connecting to the server: {e}")
    except Exception as e:
        print(e)
    finally:
        client_socket.close()
        print("Connection closed")
        exit()
