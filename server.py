import os
import shutil
import socket

def create_directory(dir_name):
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

def handle_client_commands(connection, address):
    base_dir = os.getcwd()
    create_directory(os.path.join(base_dir, "Files"))
    create_directory(os.path.join(base_dir, "Uploads"))
    current_dir = base_dir

    while True:
        command = connection.recv(1024).decode()
        cmd_parts = command.split(' ', 1)
        cmd = cmd_parts[0]

        # will be deleted later
        if cmd == 'ls':
            try:
                files = os.listdir(current_dir)
                response = '\n'.join(files) if files else "No files found."
            except Exception as e:
                response = f"Error: {e}"

        # will be deleted later
        elif cmd == 'cd':
            new_dir = os.path.join(base_dir, cmd_parts[1]) if len(cmd_parts) > 1 else base_dir
            if os.path.exists(new_dir) and new_dir in [os.path.join(base_dir, "Files"), os.path.join(base_dir, "Uploads")]:
                current_dir = new_dir
                response = f"Current directory is {os.path.basename(current_dir)}"
            else:
                response = "No such directory."

        elif cmd == 'uf': # uploading / copying the filename from 'Files' to 'Uploads'
            file_name = cmd_parts[1] if len(cmd_parts) > 1 else ""
            source_path = os.path.join(base_dir, "Files", file_name)
            destination_path = os.path.join(base_dir, "Uploads", file_name)
            if os.path.exists(source_path):
                shutil.copy(source_path, destination_path)
                response = f"File {file_name} was uploaded to 'Uploads'."
                print(f"Client {address} uploaded {file_name} to 'Uploads'") # message to the server
            else:
                response = f"File {file_name} not found in 'Files'"

        elif cmd == 'rm': # deleting files ether in Files or Uploads
            file_name = cmd_parts[1] if len(cmd_parts) > 1 else ""
            file_path = os.path.join(current_dir, file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
                response = f"File {file_name} deleted"
                print(f"Client {address} deleted {file_name} in 'Files'") # message to server
            else:
                response = "File not found"

        elif cmd == 'qp':
            response = "Disconnecting."
            connection.send(response.encode())
            print(f"Connection from {address} disconnected") # message to server
            break

        else:
            response = "Unknown command, please use -help"

        connection.send(response.encode())

    connection.close()

def start_server():
    host = '127.0.0.1'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print("Server started, waiting for connections...")

    while True:
        connection, address = server_socket.accept()
        print(f"Connection from {address}")
        handle_client_commands(connection, address)

if __name__ == "__main__":
    start_server()
