import os
import shutil
import asyncio
from crypto import handle_login_server, encryption, decryption, create_new_cipher
from asyncio import StreamReader, StreamWriter


def create_directory(dir_name: str) -> None:
    os.makedirs(dir_name, exist_ok=True)


async def handle_client_commands(reader: StreamReader, writer: StreamWriter) -> None:
    address = writer.get_extra_info("peername")
    print(f"Connection from {address}")
    base_dir = os.getcwd()
    server_name = "Uploads"
    create_directory(current_dir := os.path.join(base_dir, "Files"))
    if not (data := await handle_login_server(reader, writer)):
        print(f"Connection from {address} disconnected")  # message to server
        writer.close()
        return
    key = data[0]
    username = data[1].decode()
    create_directory(server_path := os.path.join(base_dir, server_name, username))

    while True:
        data = await reader.read(1024)
        old_salt = data[:24]
        enc_command = data[24:]
        key, salt, cipher = create_new_cipher(key, old_salt)
        if not (data := decryption(cipher, enc_command)):
            key, salt = await write(
                key, writer, "Data was corupted, please try again!", salt
            )
            continue
        command: str = data.decode()
        cmd_parts = command.split(" ", 1)
        cmd = cmd_parts[0]
        # will be deleted later
        if cmd == "ls":
            try:
                files = os.listdir(current_dir)
                response = "\n".join(files) if files else "No files found."
            except Exception as e:
                response = f"Error: {e}"

        elif cmd == "uf":  # uploading / copying the filename from 'Files' to 'Uploads'
            file_name = (cmd_parts[1] if len(cmd_parts) > 1 else "") + ".enc"
            source_path = os.path.join(base_dir, "Files", file_name)
            destination_path = os.path.join(server_path, file_name)
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
            source_path = os.path.join(server_path, file_name)
            destination_path = os.path.join(base_dir, "Files", file_name)
            if os.path.exists(source_path):
                shutil.copy(source_path, destination_path)
                response = f"File {file_name} was downloaded to 'Files'."
                print(f"Client {address} downloaded {file_name} ")  # message to server
            else:
                response = f"File {file_name} not found in 'Uploads'"

        elif cmd == "rm":  # deleting files either in Uploads
            file_name = cmd_parts[1] if len(cmd_parts) > 1 else ""
            file_path = os.path.join(server_path, file_name)
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
            await write(key, writer, response, salt)
            break

        else:
            response = "Unknown command, please use -help"

        try:
            key, salt = await write(key, writer, response, salt)
        except ConnectionResetError:
            break
    print(f"Connection from {address} disconnected")  # message to server
    writer.close()


async def write(
    key: bytes, writer: StreamWriter, response: str, salt: bytes
) -> tuple[bytes, bytes]:
    key, salt, cipher = create_new_cipher(key, salt)
    enc_response = encryption(cipher, response.encode())
    writer.write(salt + enc_response)
    await writer.drain()
    return key, salt


async def start_server() -> None:
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
