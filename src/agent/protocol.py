import contextlib
import json
import socket
import uuid

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad

MAX_FRAME_BYTES = 1024 * 1024

CONNECT_TIMEOUT_SECONDS = 10

KEEPALIVE_IDLE = 30
KEEPALIVE_INTERVAL = 10
KEEPALIVE_COUNT = 3


class FrameError(Exception):
    pass


# ---------- crypto ----------

def generate_aes_key() -> str:
    return str(uuid.uuid4())


def derive_key_bytes(aes_key: str) -> bytes:
    return SHA1.new(aes_key.encode("utf-8")).digest()[:16]


def aes_encrypt(key_bytes: bytes, data: bytes) -> bytes:
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size, style="pkcs7"))


def aes_decrypt(key_bytes: bytes, data: bytes) -> bytes:
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size, style="pkcs7")


# ---------- framing ----------

def write_frame(sock: socket.socket, data: bytes, lock=None) -> None:
    with lock if lock is not None else contextlib.nullcontext():
        sock.sendall(f"len:{len(data)}:".encode("utf-8") + b"\x00" + data)


def read_frame(sock: socket.socket, max_bytes: int | None = None) -> bytes:
    header = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            raise FrameError("connection closed")
        if b[0] == 0:
            break
        header.append(b[0])
    length_str = header.decode("utf-8", errors="ignore")
    if "len:" not in length_str:
        raise FrameError("bad frame header: " + length_str)
    start = length_str.index("len:") + 4
    end = length_str.rindex(":")
    try:
        length = int(length_str[start:end])
    except ValueError:
        raise FrameError("bad frame length: " + length_str)
    if max_bytes is not None and length > max_bytes:
        raise FrameError("frame too large: " + str(length))
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise FrameError("connection closed mid-frame")
        data.extend(chunk)
    return bytes(data)


# ---------- tcp ----------

def enable_tcp_keepalive(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
    if hasattr(socket, "TCP_KEEPINTVL"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
    if hasattr(socket, "TCP_KEEPCNT"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)


def connect_tcp(host: str, port: int, *, nodelay: bool = False,
                timeout: float | None = None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if timeout is not None:
        sock.settimeout(timeout)
    if nodelay:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    enable_tcp_keepalive(sock)
    sock.connect((host, port))
    return sock


# ---------- handshake ----------

def perform_handshake(sock: socket.socket, rsa_cipher: PKCS1_v1_5.PKCS115_Cipher,
                      payload: dict, aes_key: str) -> tuple[str, bytes]:
    key_bytes = derive_key_bytes(aes_key)
    write_frame(sock, rsa_cipher.encrypt(json.dumps(payload).encode("utf-8")))
    frame = read_frame(sock, max_bytes=MAX_FRAME_BYTES)
    hello = aes_decrypt(key_bytes, frame).decode("utf-8")
    return hello, key_bytes
