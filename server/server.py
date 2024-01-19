import os
import shutil
import asyncio
from crypto import (
    handle_login_server,
    encryption,
    decryption,
    create_new_cipher,
    write_log,
)
from asyncio import StreamReader, StreamWriter

folder_size_per_user = 5

if not os.path.exists("log.txt"):
    with open("log.txt", "w"):
        pass


# input vaildation to path traversal
def safe_path(base_path: str, path: str, follow_symlinks=True) -> bool:
    if follow_symlinks:
        return os.path.realpath(path).startswith(base_path)
    else:
        return os.path.abspath(path).startswith(base_path)


def create_directory(dir_name: str) -> None:
    os.makedirs(dir_name, exist_ok=True)


def directory_size(path: str) -> int:
    total_size = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            total_size += os.path.getsize(fp)
    return total_size


def is_within_limit(size_to_add: int, current_dir: str) -> bool:
    current_size = directory_size(current_dir)
    limit = folder_size_per_user * (1024) ** 3
    return (current_size + size_to_add) <= limit


async def handle_client_commands(reader: StreamReader, writer: StreamWriter) -> None:
    address = writer.get_extra_info("peername")
    write_log(f"Connection from {address}")
    base_dir = os.getcwd()
    server_name = "Uploads"
    create_directory(current_dir := os.path.join(base_dir, "../client/Files"))
    try:
        data = await asyncio.wait_for(handle_login_server(reader, writer), timeout=1000)
    except TimeoutError:
        data = b""
    if not data:
        write_log(f"Connection from {address} disconnected")
        writer.close()
        return

    key = data[0]
    username = data[1].decode()
    create_directory(server_path := os.path.join(base_dir, server_name, username))
    tries = 10
    while tries > 0:
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1000)
        except TimeoutError:
            write_log(f"{username} {address} has reached the timeout")
            break
        old_salt = data[:24]
        enc_command = data[24:]
        key, salt, cipher = create_new_cipher(key, old_salt)
        if not (data := decryption(cipher, enc_command)):
            write_log(f"Data from {username} {address} was corupted")
            key, salt = await write(
                key, writer, "Data was corupted, please try again!", salt
            )
            tries -= 2
            continue
        command: str = data.decode()
        cmd_parts = command.split(" ", 1)
        cmd = cmd_parts[0]

        if cmd == "ls":
            try:
                files = os.listdir(server_path)
                response = "\n".join(files) if files else "No files found."
            except Exception as e:
                response = f"Error: {e}"

        elif cmd == "uf":  # uploading / copying the filename from 'Files' to 'Uploads'
            file_name = f"{cmd_parts[1] if len(cmd_parts) > 1 else ''}.enc"
            source_path = os.path.abspath(os.path.join(current_dir, file_name))
            destination_path = os.path.abspath(os.path.join(server_path, file_name))

            if safe_path(server_path, destination_path) and os.path.exists(source_path):
                if is_within_limit(os.path.getsize(source_path), server_path):
                    shutil.copy(source_path, destination_path)
                    os.chmod(destination_path, 0o660)
                    response = f"File {file_name} was uploaded."
                else:
                    response = (
                        f"Upload failed. Limit of {folder_size_per_user}GB exceeded."
                    )
                    write_log(f"{username} {address} exceeded the limit of file space")
            else:
                response = f"File {file_name} not found in 'Files'"
                if not safe_path(server_path, source_path):
                    write_log(
                        f"{username} {address} tried to upload to a folder ({source_path}), which he has no permission to access"
                    )
                    tries -= 1

        elif cmd == "df":  # download / copy file from 'Uploads' to 'Files'
            file_name = f"{cmd_parts[1] if len(cmd_parts) > 1 else ''}.enc"
            source_path = os.path.abspath(os.path.join(server_path, file_name))
            destination_path = os.path.abspath(os.path.join(current_dir, file_name))

            if safe_path(server_path, source_path) and os.path.exists(source_path):
                shutil.copy(source_path, destination_path)
                response = f"File {file_name} was downloaded to 'Files'."
            else:
                response = f"File {file_name} not found"
                if not safe_path(server_path, source_path):
                    write_log(
                        f"{username} {address} tried to download a file ({source_path}), which he has no permission to access"
                    )
                    tries -= 1

        elif cmd == "rm":  # deleting files either in Uploads
            file_name = f"{cmd_parts[1] if len(cmd_parts) > 1 else ''}.enc"
            file_path = os.path.join(server_path, file_name)
            if safe_path(server_path, file_path) and os.path.exists(file_path):
                os.remove(file_path)
                response = f"File {file_name} deleted"
                log_message = f"Client {address} deleted {file_name} in 'Files'"
                with open("log.txt", "a") as file:
                    file.write(log_message + "\n")
            else:
                response = "File not found"
                if not safe_path(server_path, file_path):
                    write_log(
                        f"{username} {address} tried to delete a file ({file_path}), which he has no permission to access"
                    )
                    tries -= 1

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
    write_log(f"Connection from {address} disconnected")
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
