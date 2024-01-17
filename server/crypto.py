from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA3_512, Hash
from cryptography.exceptions import InvalidTag
from opaque import (
    Ids,
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
LIMIT = 2**31 - 1

Password = {b"": b""}
user_salt = b"\x05&\xbe_-\x19\xcbLIRK]\x00\xbb\xa6)\x9fa]\xdf\xbb\x1a\xfb4"


def write_log(log_message: str) -> None:
    with open("log.txt", "a") as file:
        file.write(log_message + "\n")
    print(log_message)


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
    data = await reader.read(3)
    if not data:
        return False
    return await (login_server if data == b"yes" else register_server)(reader, writer)


async def register_server(
    reader: StreamReader, writer: StreamWriter
) -> tuple[bytes, bytes] | Literal[False]:
    global Password
    address = writer.get_extra_info("peername")
    while True:
        data = await reader.read(96)
        if not data:
            return False
        username, M = (
            base64.urlsafe_b64encode(derive_key_from_password(data[:64], user_salt)),
            data[64:],
        )
        username_database = ""
        if username_database:
            write_log(
                f"{username.decode()} {address} attempted to create a new account with an already existing username"
            )
            writer.write("Retry".encode())
            continue
        secS, pub = CreateRegistrationResponse(M)
        writer.write(pub)
        rec0 = await reader.read(192)
        if not rec0:
            return False
        rec1 = StoreUserRecord(secS, rec0)
        # create new User with password and username
        Password[username] = rec1
        write_log(f"{username.decode()} {address} created a new account")
        return await login_server(reader, writer)


async def login_server(
    reader: StreamReader, writer: StreamWriter
) -> tuple[bytes, bytes] | Literal[False]:
    tries = 5
    address = writer.get_extra_info("peername")
    username = ""
    while tries > 0:
        data = await reader.read(160)  # Read username + public key
        if not data:
            return False
        username, pub = data[:64], data[64:]

        ids = Ids(username, "server")
        username = base64.urlsafe_b64encode(
            derive_key_from_password(username, user_salt)
        )
        try:
            # get rec from Database by username
            rec = Password[username]
        except Exception:
            writer.write("Retry".encode())
            tries -= 1
            continue
        resp, sk, secS = CreateCredentialResponse(pub, rec, ids, "")
        writer.write(resp)
        if (data := await reader.read(116)) == "Retry".encode():  # Read salt + encauthU
            write_log(f"{username.decode()} {address} failed on login")
            tries -= 1
            continue
        if not data:
            return False
        salt, encauthU = data[:24], data[24:]
        key_sk = derive_key_from_password(sk, salt)
        cipher = ChaCha20Poly1305(key_sk)
        authU = decryption(cipher, encauthU)
        if UserAuth(secS, authU) is not None:
            write_log(f"{username.decode()} {address} failed on login")
            writer.write("Login failed!".encode())
            tries -= 1
            continue
        writer.write(("works").encode())
        write_log(f"{username.decode()} {address} has performed a login")
        return key_sk, username
    write_log(f"{username.decode()} {address} has reached the limit on false Passwords")
    writer.write("You have tried to many times! Please try later again".encode())
    return False


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
