import socket

# For File Encryption
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA3_512, Hash
from cryptography.exceptions import InvalidTag
from opaque import (
    Ids,
    CreateRegistrationRequest,
    FinalizeRequest,
    CreateCredentialRequest,
    RecoverCredentials,
)
import os
from argon2.low_level import Type, hash_secret_raw

from typing import Literal
from getpass import getpass

SALT_SIZE = 12
LIMIT = 2**31 - 1
FILE_KEY = "secret.txt"


def derive_key_from_password(password: bytes, salt: bytes) -> bytes:
    derived_key = hash_secret_raw(password, salt, 50, 102400, 50, 32, Type.ID)
    return derived_key


def good_hash(input: str) -> bytes:
    hash = SHA3_512()
    digest = Hash(hash, None)
    digest.update(input.encode())
    return digest.finalize()


def handle_login_user(
    client_socket: socket.socket,
) -> tuple[bytes, bytes | Literal[0]] | Literal[False]:
    has_login = "yes" if input("Have already an account? (y/n) ") == "y" else "no"
    client_socket.send(has_login.encode())
    return (login_user if has_login == "yes" else register_user)(client_socket)


def register_user(
    client_socket: socket.socket,
) -> tuple[bytes, bytes | Literal[0]] | Literal[False]:
    while True:
        print("Registration: ")
        username = good_hash(input("Username: "))
        password = getpass("Password: ")
        ids = Ids(username, "server")

        secU, M = CreateRegistrationRequest(password)
        client_socket.send(username + M)
        if (pub := client_socket.recv(64)) == "Retry".encode():
            print("Please try again!")
            continue
        rec0, _ = FinalizeRequest(secU, pub, ids)
        client_socket.send(rec0)
        create_key(password.encode())
        return login_user(client_socket)


def login_user(
    client_socket: socket.socket,
) -> tuple[bytes, bytes | Literal[0]] | Literal[False]:
    mes = ""
    print("Login:")
    while True:
        username = good_hash(input("Username: "))
        password = getpass("Password: ")
        ids = Ids(
            username,
            "server",
        )

        pub, secU = CreateCredentialRequest(password)
        client_socket.send(username + pub)
        if (resp := client_socket.recv(320)) == "Retry".encode():
            print("Please try again!")
            continue
        try:
            sk, authU, _ = RecoverCredentials(resp, secU, "", ids)
        except ValueError as e:
            print(e)
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
        print("Login was succesfull!")
        key = get_key(password.encode())
        return key_sk, key
    print(mes)
    return False


def read_file(file_path: str) -> bytes:
    try:
        with open(file_path, "rb") as file:
            text = file.read()
    except FileNotFoundError:
        print("File not found!")
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
        return 3
    return 0


def filecryption(file_path: str, encrypt: bool, key: bytes) -> int:
    cipher = ChaCha20Poly1305(key)
    if (text := read_file(file_path + ".enc" * (not encrypt))) == b"1":
        return 1
    if not (text := (encryption if encrypt else decryption)(cipher, text)):
        return 2
    return write_file(file_path + ".enc" * encrypt, text)


def encryption(cipher: ChaCha20Poly1305, plaintext: bytes) -> bytes:
    ciphertext = b""
    while plaintext:
        plain_block = plaintext[:LIMIT]
        salt = os.urandom(SALT_SIZE)
        cipher_block = cipher.encrypt(salt, plain_block, None)
        plaintext = plaintext[LIMIT:]
        ciphertext += salt + cipher_block
    return ciphertext


def decryption(cipher: ChaCha20Poly1305, data: bytes) -> Literal[0] | bytes:
    plaintext = b""
    while data:
        data_block = data[: LIMIT + 28]
        salt = data_block[:SALT_SIZE]
        ciphertext = data_block[SALT_SIZE:]
        try:
            plain_block = cipher.decrypt(salt, ciphertext, None)
        except InvalidTag:
            return 0
        data = data[LIMIT + 28 :]
        plaintext += plain_block
    return plaintext


def create_new_cipher(
    key: bytes, salt: bytes = b""
) -> tuple[bytes, bytes, ChaCha20Poly1305]:
    if not salt:
        salt = os.urandom(24)
    new_key = derive_key_from_password(key, salt)
    cipher = ChaCha20Poly1305(new_key)
    return key, salt, cipher


def create_key(password: bytes) -> None:
    salt = os.urandom(24)
    key = derive_key_from_password(password, salt)
    cipher = ChaCha20Poly1305(key)
    file_key = os.urandom(32)
    cipher_key = encryption(cipher, file_key)
    write_file(FILE_KEY, salt + cipher_key)


def get_key(password: bytes) -> bytes | Literal[0]:
    data = read_file(FILE_KEY)
    salt = data[:24]
    cipher_key = data[24:]
    key = derive_key_from_password(password, salt)
    cipher = ChaCha20Poly1305(key)
    file_key = decryption(cipher, cipher_key)
    return file_key
