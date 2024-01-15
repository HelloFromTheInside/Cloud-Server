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
    print("cd <directory> - Changes the current directory")
    print("uf <filename> - Copies the file from 'Files' to 'Uploads'")
    print("qp - Ends the connection to the server")
    print("-help - Shows this help")


if __name__ == "__main__":
    host = "127.0.0.1"
    port = 12345
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    try:
        salt = b""
        if not (key := handle_login_user(client_socket)):
            raise socket.timeout
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
                if filecryption(file_name, True):
                    continue
            elif cmd_parts[0] == "df":
                key, salt = send_command(key, salt, command)
                file_name = "Files/" + (cmd_parts[1] if len(cmd_parts) > 1 else "")
                if filecryption(file_name, False):
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
