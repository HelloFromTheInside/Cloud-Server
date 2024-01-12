import os
import shutil
import asyncio
from crypto import handle_login_server


def create_directory(dir_name):
    os.makedirs(dir_name, exist_ok=True)


async def handle_client_commands(reader, writer):
    address = writer.get_extra_info("peername")
    print(f"Connection from {address}")
    base_dir = os.getcwd()
    create_directory(os.path.join(base_dir, "Files"))
    create_directory(os.path.join(base_dir, "Uploads"))
    current_dir = os.path.join(base_dir, "Files")

    while True:
        if not (data := await handle_login_server(reader, writer)):
            break
        else:
            session_key = data[0]
            username = data[1].decode()
            create_directory(os.path.join(base_dir, "Uploads", username))
        command = (await reader.read(100)).decode()
        cmd_parts = command.split(" ", 1)
        cmd = cmd_parts[0]
        print(username, session_key)
        # will be deleted later
        if cmd == "ls":
            try:
                files = os.listdir(current_dir)
                response = "\n".join(files) if files else "No files found."
            except Exception as e:
                response = f"Error: {e}"

        # will be deleted later
        # elif cmd == 'cd':
        # new_dir = os.path.join(base_dir, cmd_parts[1]) if len(cmd_parts) > 1 else base_dir
        # if os.path.exists(new_dir) and new_dir in [os.path.join(base_dir, "Files"), os.path.join(base_dir, "Uploads")]:
        # current_dir = new_dir
        # response = f"Current directory is {os.path.basename(current_dir)}"
        # else:
        # response = "No such directory."

        elif cmd == "uf":  # uploading / copying the filename from 'Files' to 'Uploads'
            file_name = (cmd_parts[1] if len(cmd_parts) > 1 else "") + ".enc"
            source_path = os.path.join(base_dir, "Files", file_name)
            destination_path = os.path.join(base_dir, "Uploads", username, file_name)
            if os.path.exists(source_path):
                shutil.copy(source_path, destination_path)
                response = f"File {file_name} was uploaded to 'Uploads'."
                print(
                    f"Client {address} uploaded {file_name} to 'Uploads'"
                )  # message to the server
            else:
                response = f"File {file_name} not found in 'Files'"

        elif cmd == "df":  # download / copy file from 'Uploads' to 'Files'
            file_name = (
                cmd_parts[1] if len(cmd_parts) > 1 else ""
            ) + ".enc"  # checks if there's additional text after 'df'
            source_path = os.path.join(base_dir, "Uploads", username, file_name)
            destination_path = os.path.join(base_dir, "Files", file_name)
            if os.path.exists(source_path):
                shutil.copy(source_path, destination_path)
                response = f"File {file_name} was downloaded to 'Files'."
                print(f"Client {address} downloaded {file_name} ")  # message to server
            else:
                response = f"File {file_name} not found in 'Uploads'"

        elif cmd == "rm":  # deleting files ether in Files or Uploads
            file_name = cmd_parts[1] if len(cmd_parts) > 1 else ""
            file_path = os.path.join(current_dir, file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
                response = f"File {file_name} deleted"
                print(
                    f"Client {address} deleted {file_name} in 'Files'"
                )  # message to server
            else:
                response = "File not found"

        elif cmd == "qp":
            response = "Disconnecting."
            writer.write(response.encode())
            await writer.drain()
            print(f"Connection from {address} disconnected")  # message to server
            break

        else:
            response = "Unknown command, please use -help"

        writer.write(response.encode())
        try:
            await writer.drain()
        except ConnectionResetError:
            print(f"Connection from {address} disconnected")  # message to server
            break

    writer.close()


async def start_server():
    max_connections = 5

    server = await asyncio.start_server(
        handle_client_commands,
        "127.0.0.1",
        12345,
        limit=max_connections,
    )

    addr = server.sockets[0].getsockname()
    print(
        f"Serving on {addr} with a maximum of {max_connections} concurrent connections"
    )

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(start_server())
    except KeyboardInterrupt:
        print("The Server closed!")
