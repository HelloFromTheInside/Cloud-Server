import socket

# For File Encryption
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.hashes import SHA3_512, Hash
from secret import key
from opaque import (
    Ids,
    CreateRegistrationRequest,
    FinalizeRequest,
    CreateCredentialRequest,
    RecoverCredentials,
    CreateRegistrationResponse,
    StoreUserRecord,
    CreateCredentialResponse,
    UserAuth,
)
import os
from argon2.low_level import Type, hash_secret_raw

from typing import Literal
from asyncio import StreamReader, StreamWriter
import base64

SALT_SIZE = 12

Username = b""
Password = b""


def derive_key_from_password(password: bytes, salt: bytes) -> bytes:
    derived_key = hash_secret_raw(password, salt, 50, 102400, 50, 32, Type.ID)
    return derived_key


def good_hash(input: str) -> bytes:
    hash = SHA3_512()
    digest = Hash(hash, None)
    digest.update(input.encode())
    return digest.finalize()


async def handle_login_server(
    reader: StreamReader, writer: StreamWriter
) -> tuple[bytes, bytes] | Literal[False]:
    return await (login_server if await reader.read(3) == b"yes" else register_server)(
        reader, writer
    )


async def register_server(
    reader: StreamReader, writer: StreamWriter
) -> tuple[bytes, bytes] | Literal[False]:
    global Username, Password
    data = await reader.read(96)
    username = data[:64]
    M = data[64:]
    secS, pub = CreateRegistrationResponse(M)
    writer.write(pub)
    rec0 = await reader.read(192)
    rec1 = StoreUserRecord(secS, rec0)
    # create new User with password and username
    Username = username
    Password = rec1
    return await login_server(reader, writer)


async def login_server(
    reader: StreamReader, writer: StreamWriter
) -> tuple[bytes, bytes] | Literal[False]:
    tries = 5
    while tries > 0:
        data = await reader.read(160)  # Read username + publich key
        username, pub = data[:64], data[64:]
        ids = Ids(username, "server")
        # get rec from Database by username
        rec = Password
        resp, sk, secS = CreateCredentialResponse(pub, rec, ids, "")
        writer.write(resp)
        if (data := await reader.read(116)) == "Retry".encode():  # Read salt + encauthU
            print("Login failed.")
            tries -= 1
            continue
        salt, encauthU = data[:24], data[24:]
        key_sk = derive_key_from_password(sk, salt)
        cipher = ChaCha20Poly1305(key_sk)
        authU = decryption(cipher, encauthU)
        if UserAuth(secS, authU) is not None:
            print("Login failed.")
            tries -= 1
            continue
        writer.write(("works").encode())
        print("Login was succesfull")
        return key_sk, username
    writer.write("You have tried to many times! Please try later again".encode())
    return False


def handle_login_user(client_socket: socket.socket) -> bytes | Literal[False]:
    has_login = "yes" if input("Have already an account? (y/n) ") == "y" else "no"
    client_socket.send(has_login.encode())
    return (login_user if has_login == "yes" else register_user)(client_socket)


def register_user(client_socket: socket.socket) -> bytes | Literal[False]:
    username = base64.urlsafe_b64encode(good_hash(input("Username: ")))
    password = input("Passwort: ")
    ids = Ids(username, "server")

    secU, M = CreateRegistrationRequest(password)
    client_socket.send(username + M)
    pub = client_socket.recv(64)
    rec0, _ = FinalizeRequest(secU, pub, ids)
    client_socket.send(rec0)
    return login_user(client_socket)


def login_user(client_socket: socket.socket) -> bytes | Literal[False]:
    mes = ""
    while True:
        username = base64.urlsafe_b64encode(good_hash(input("Username: ")))
        password = input("Passwort: ")
        ids = Ids(username, "server")

        pub, secU = CreateCredentialRequest(password)
        client_socket.send(username + pub)
        resp = client_socket.recv(320)
        try:
            sk, authU, _ = RecoverCredentials(resp, secU, "", ids)
        except ValueError:
            print("Login failed.")
            client_socket.send("Retry".encode())
            continue
        salt = os.urandom(24)
        key_sk = derive_key_from_password(sk, salt)
        cipher = ChaCha20Poly1305(key_sk)
        enc_authU = encryption(cipher, authU)
        client_socket.send(salt + enc_authU)
        if mes := client_socket.recv(52).decode() != ("works"):
            break
        return key_sk
    print(mes)
    return False


def readfile(file_path: str) -> bytes:
    try:
        with open(file_path, "rb") as file:
            text = file.read()
    except FileNotFoundError:
        print("The file does not exist.")
        return b"1"
    except Exception as e:
        print(f"An error occurred: {e}")
        return b"1"
    return text


def write_file(file_path: str, text: bytes) -> int:
    try:
        with open(file_path, "wb") as file:
            file.write(text)
    except Exception as e:
        print(f"An error occurred: {e}")
        return 1
    return 0


def filecryption(file_path: str, encrypt: bool) -> int:
    cipher = ChaCha20Poly1305(key)
    if (text := readfile(file_path + ".enc" * (not encrypt))) == b"1":
        return 1
    if not (text := (encryption if encrypt else decryption)(cipher, text)):
        return 2
    return write_file(file_path + ".enc" * encrypt, text)


def encryption(cipher: ChaCha20Poly1305, plaintext: bytes) -> bytes:
    salt = os.urandom(SALT_SIZE)
    ciphertext = cipher.encrypt(salt, plaintext, None)
    return salt + ciphertext


def decryption(cipher: ChaCha20Poly1305, data: bytes) -> Literal[0] | bytes:
    salt = data[:SALT_SIZE]
    ciphertext = data[SALT_SIZE:]
    try:
        plaintext = cipher.decrypt(salt, ciphertext, None)
    except InvalidTag:
        return 0
    return plaintext
