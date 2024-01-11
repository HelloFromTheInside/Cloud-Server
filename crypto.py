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

SALT_SIZE = 12


def derive_key_from_password(password, salt):
    derived_key = hash_secret_raw(password, salt, 50, 102400, 50, 32, Type.ID)
    return derived_key


def hash(input: str):
    hash = SHA3_512()
    digest = Hash(hash, None)
    digest.update(input.encode())
    return digest.finalize()


async def register_server(reader, writer):
    M = await reader.read(32)
    skS = ""
    secS, pub = CreateRegistrationResponse(M, skS)
    writer.write(pub)
    rec0 = await reader.read(192)
    rec1 = StoreUserRecord(secS, rec0)
    # create new User with password and username


async def login_server(reader, writer):
    data = await reader.read(160)
    username = data[:64]
    pub = data[64:]
    ids = Ids(username, "server")
    # get rec from Database
    rec = ""
    context = ""
    resp, sk, secS = CreateCredentialResponse(pub, rec, ids, context)
    writer.write(resp)
    encauthU = await reader.read(92)
    cipher = ChaCha20Poly1305(sk)
    authU = decryption(cipher, encauthU)
    if UserAuth(secS, authU) != 0:
        return 1
    return


def register_user(client_socket: socket.socket):
    username = hash(input("Username: "))
    password = input("Passwort: ")
    ids = Ids(username, "server")

    secU, M = CreateRegistrationRequest(password)
    client_socket.send(M)
    pub = client_socket.recv(64)
    rec0, _ = FinalizeRequest(secU, pub, ids)
    client_socket.send(rec0)


def login_user(client_socket: socket.socket):
    username = hash(input("Username: "))
    password = input("Passwort: ")
    ids = Ids(username, "server")

    pub, secU = CreateCredentialRequest(password)
    client_socket.send(username + pub)
    resp = client_socket.recv(320)
    ctx = ""
    sk, authU, _ = RecoverCredentials(resp, secU, ctx, ids)
    cipher = ChaCha20Poly1305(sk)
    enc_authU = encryption(cipher, authU)
    client_socket.send(enc_authU)
    return sk


def readfile(file_path: str):
    try:
        with open(file_path, "rb") as file:
            text = file.read()
    except FileNotFoundError:
        print("The file does not exist.")
        return 1
    except Exception as e:
        print(f"An error occurred: {e}")
        return 1
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
    if (text := readfile(file_path + ".enc" * (not encrypt))) == 1:
        return 1
    if (text := (encryption if encrypt else decryption)(cipher, text)) == 1:
        return 2
    return write_file(file_path + ".enc" * encrypt, text)


def encryption(cipher: ChaCha20Poly1305, plaintext: bytes) -> bytes:
    salt = os.urandom(SALT_SIZE)
    ciphertext = cipher.encrypt(salt, plaintext, None)
    return salt + ciphertext


def decryption(cipher: ChaCha20Poly1305, data: bytes):
    salt = data[:SALT_SIZE]
    ciphertext = data[SALT_SIZE:]
    try:
        plaintext = cipher.decrypt(salt, ciphertext, None)
    except InvalidTag:
        return 1
    return plaintext
