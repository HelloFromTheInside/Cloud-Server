import socket

def send_command(command):
    try:
        client_socket.send(command.encode())
        response = client_socket.recv(1024).decode()
        print(response)
    except Exception as e:
        print(f"Error sending command: {e}")

# ls & cd only for navigation
def display_help():
    print("Available commands:")
    print("ls - Lists all files in the current directory")
    print("cd <directory> - Changes the current directory")
    print("uf <filename> - Copies the file from 'Files' to 'Uploads'")
    print("qp - Ends the connection to the server")
    print("-help - Shows this help")

host = '127.0.0.1'
port = 12345

try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
except Exception as e:
    print(f"Error connecting to the server: {e}")
    exit()

while True:
    command = input(">>> ")
    if command == '-help':
        display_help()
    else:
        send_command(command)

    if command == 'qp':
        break

client_socket.close()
