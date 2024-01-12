import socket
from crypto import filecryption, handle_login_user, encryption, decryption
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def send_command(cipher, command) -> None:
    enc_command = encryption(cipher, command)
    client_socket.send(enc_command)
    enc_response = client_socket.recv(1024)
    if not (response := decryption(cipher, enc_response)):
        print("File is corrupted, please continue with precaution!")
        return
    print(response)


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
        if not (session_key := handle_login_user(client_socket)):
            raise socket.timeout
        cipher = ChaCha20Poly1305(session_key)
        while True:
            command = input(">>> ")
            cmd_parts = command.split(" ", 1)

            if command == "-help":
                display_help()
                continue
            elif cmd_parts[0] == "uf":
                file_name = "Files/" + (cmd_parts[1] if len(cmd_parts) > 1 else "")
                if filecryption(file_name, True):
                    continue
            elif cmd_parts[0] == "df":
                send_command(cipher, command)
                file_name = "Files/" + (cmd_parts[1] if len(cmd_parts) > 1 else "")
                if filecryption(file_name, False):
                    print("File is corrupted, please continue with precaution!")
                continue
            send_command(cipher, command)
            if command == "qp":
                break
    except socket.timeout as e:
        print(f"Error connecting to the server: {e}")
    finally:
        client_socket.close()
        print("Connection closed")
        exit()
