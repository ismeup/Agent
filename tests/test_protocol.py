import base64
import json
import socket
import threading
import time

import pytest
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from agent import protocol
from agent.client.remote_client import RemoteClient


def _socketpair():
    a, b = socket.socketpair()
    return a, b


# ---------- crypto ----------

def test_aes_encrypt_decrypt_roundtrip():
    key = protocol.generate_aes_key()
    key_bytes = protocol.derive_key_bytes(key)
    assert len(key_bytes) == 16
    for data in (b"", b"x", b"hello world" * 100):
        assert protocol.aes_decrypt(key_bytes, protocol.aes_encrypt(key_bytes, data)) == data


def test_derive_key_bytes_deterministic():
    a = protocol.derive_key_bytes("same-key")
    b = protocol.derive_key_bytes("same-key")
    assert a == b
    assert protocol.derive_key_bytes("other-key") != a


# ---------- framing ----------

def test_frame_roundtrip():
    a, b = _socketpair()
    try:
        for payload in (b"", b"x", b"y" * 65536):
            protocol.write_frame(a, payload)
            assert protocol.read_frame(b) == payload
    finally:
        a.close()
        b.close()


def test_frame_no_limit_allows_large_payload():
    a, b = _socketpair()
    payload = b"z" * (protocol.MAX_FRAME_BYTES + 1024)
    result = {}

    def writer():
        try:
            protocol.write_frame(a, payload)
        except Exception as e:
            result["error"] = e

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    try:
        assert protocol.read_frame(b) == payload
        t.join(timeout=5)
        assert not t.is_alive()
        assert "error" not in result
    finally:
        a.close()
        b.close()


def test_frame_too_large_rejected():
    a, b = _socketpair()
    try:
        a.sendall(b"len:2000000:\x00")
        with pytest.raises(protocol.FrameError, match="too large"):
            protocol.read_frame(b, max_bytes=protocol.MAX_FRAME_BYTES)
    finally:
        a.close()
        b.close()


def test_frame_bad_header():
    a, b = _socketpair()
    try:
        a.sendall(b"garbage\x00")
        with pytest.raises(protocol.FrameError):
            protocol.read_frame(b)
    finally:
        a.close()
        b.close()


def test_frame_bad_length():
    a, b = _socketpair()
    try:
        a.sendall(b"len:abc:\x00")
        with pytest.raises(protocol.FrameError):
            protocol.read_frame(b)
    finally:
        a.close()
        b.close()


def test_frame_closed_connection():
    a, b = _socketpair()
    a.close()
    with pytest.raises(protocol.FrameError):
        protocol.read_frame(b)
    b.close()


def test_frame_truncated_payload():
    a, b = _socketpair()
    try:
        a.sendall(b"len:5:\x00abc")
        a.close()
        with pytest.raises(protocol.FrameError):
            protocol.read_frame(b)
    finally:
        b.close()


def test_write_frame_with_lock():
    a, b = _socketpair()
    lock = threading.Lock()
    try:
        protocol.write_frame(a, b"first", lock)
        protocol.write_frame(a, b"second", lock)
        assert protocol.read_frame(b) == b"first"
        assert protocol.read_frame(b) == b"second"
    finally:
        a.close()
        b.close()


# ---------- tcp ----------

def test_connect_tcp_keepalive_nodelay_timeout():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    try:
        sock = protocol.connect_tcp("127.0.0.1", port, nodelay=True, timeout=5)
        conn, _ = server.accept()
        try:
            assert sock.gettimeout() == 5
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 1
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 1
            if hasattr(socket, "TCP_KEEPIDLE"):
                assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == protocol.KEEPALIVE_IDLE
            if hasattr(socket, "TCP_KEEPINTVL"):
                assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL) == protocol.KEEPALIVE_INTERVAL
            if hasattr(socket, "TCP_KEEPCNT"):
                assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT) == protocol.KEEPALIVE_COUNT
        finally:
            sock.close()
            conn.close()
    finally:
        server.close()


# ---------- handshake ----------

def test_perform_handshake():
    server_key = RSA.generate(2048)
    public_b64 = base64.b64encode(server_key.publickey().export_key(format="DER")).decode()
    client_cipher = PKCS1_v1_5.new(RSA.import_key(base64.b64decode(public_b64)))

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def run_server():
        conn, _ = server.accept()
        try:
            frame = protocol.read_frame(conn)
            decrypted = PKCS1_v1_5.new(server_key).decrypt(frame, None)
            handshake = json.loads(decrypted.decode())
            key_bytes = protocol.derive_key_bytes(handshake["aes"])
            protocol.write_frame(conn, protocol.aes_encrypt(key_bytes, b"HELLO:uid-x"))
        finally:
            conn.close()

    threading.Thread(target=run_server, daemon=True).start()

    try:
        sock = protocol.connect_tcp("127.0.0.1", port, timeout=5)
        aes_key = protocol.generate_aes_key()
        hello, key_bytes = protocol.perform_handshake(
            sock, client_cipher,
            {"uid": "uid-x", "aes": aes_key, "version": 1},
            aes_key,
        )
        assert hello == "HELLO:uid-x"
        assert key_bytes == protocol.derive_key_bytes(aes_key)
    finally:
        server.close()


# ---------- remote client connection ----------

class _StubManager:
    def __init__(self):
        self.added = []
        self.removed = []

    def add_thread(self, client):
        self.added.append(client)

    def remove_thread(self, client):
        self.removed.append(client)

    def get_thread_id(self, client):
        return "0"


class _FakeConnectionData:
    def __init__(self, host, port):
        self._host = host
        self._port = port

    def get_host(self):
        return self._host

    def get_port(self):
        return self._port


def _backend_server(private_key, identity, respond=True):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def run_server():
        try:
            conn, _ = server.accept()
        except OSError:
            return
        try:
            if respond:
                frame = protocol.read_frame(conn)
                decrypted = PKCS1_v1_5.new(private_key).decrypt(frame, None)
                if decrypted is not None:
                    handshake = json.loads(decrypted.decode())
                    key_bytes = protocol.derive_key_bytes(handshake["aes"])
                    protocol.write_frame(
                        conn, protocol.aes_encrypt(key_bytes, f"HELLO{identity}".encode())
                    )
            while True:
                data = conn.recv(1)
                if not data:
                    break
        except (OSError, protocol.FrameError, ValueError, TypeError):
            pass
        finally:
            conn.close()

    threading.Thread(target=run_server, daemon=True).start()
    return server, port


def test_connect_uses_timeout_and_clears_it_after_handshake(monkeypatch):
    server_key = RSA.generate(2048)
    cipher = PKCS1_v1_5.new(server_key.publickey())
    server, port = _backend_server(server_key, "identity-1", respond=True)

    calls = []
    real_connect = protocol.connect_tcp

    def spy_connect(host, port_, **kwargs):
        calls.append(kwargs)
        return real_connect(host, port_, **kwargs)

    monkeypatch.setattr(protocol, "connect_tcp", spy_connect)

    manager = _StubManager()
    client = RemoteClient(manager, _FakeConnectionData("127.0.0.1", port), "identity-1", cipher)
    thread = threading.Thread(target=client.connect, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline and not client.ready:
        time.sleep(0.02)
    assert client.ready, "client did not become ready"
    try:
        assert calls, "connect_tcp was not called"
        assert calls[0].get("timeout") == protocol.CONNECT_TIMEOUT_SECONDS
        assert client.socket is not None
        assert client.socket.gettimeout() is None
    finally:
        client.disconnect()
        thread.join(timeout=5)
        server.close()


def test_handshake_includes_capabilities(monkeypatch):
    server_key = RSA.generate(2048)
    cipher = PKCS1_v1_5.new(server_key.publickey())
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    handshake = {}

    def run_server():
        conn, _ = server.accept()
        try:
            frame = protocol.read_frame(conn)
            decrypted = PKCS1_v1_5.new(server_key).decrypt(frame, None)
            if decrypted is not None:
                handshake.update(json.loads(decrypted.decode()))
                key_bytes = protocol.derive_key_bytes(handshake["aes"])
                protocol.write_frame(
                    conn, protocol.aes_encrypt(key_bytes, b"HELLOidentity-cap")
                )
            while True:
                data = conn.recv(1)
                if not data:
                    break
        except (OSError, protocol.FrameError):
            pass
        finally:
            conn.close()

    threading.Thread(target=run_server, daemon=True).start()

    monkeypatch.setattr("agent.client.remote_client.ENABLE_WOL", True)
    monkeypatch.setattr("agent.client.remote_client.ENABLE_PORT_PROXY", False)

    manager = _StubManager()
    client = RemoteClient(manager, _FakeConnectionData("127.0.0.1", port), "identity-cap", cipher)
    thread = threading.Thread(target=client.connect, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while time.time() < deadline and not client.ready:
        time.sleep(0.02)
    assert client.ready, "client did not become ready"
    try:
        assert handshake.get("capabilities") == {"wake_on_lan": True, "port_proxy": False}
    finally:
        client.disconnect()
        thread.join(timeout=5)
        server.close()


def test_connect_times_out_against_silent_server(monkeypatch):
    server_key = RSA.generate(2048)
    cipher = PKCS1_v1_5.new(server_key.publickey())
    server, port = _backend_server(server_key, "identity-1", respond=False)

    monkeypatch.setattr(protocol, "CONNECT_TIMEOUT_SECONDS", 1)

    manager = _StubManager()
    client = RemoteClient(manager, _FakeConnectionData("127.0.0.1", port), "identity-1", cipher)
    started = time.time()
    client.run()
    elapsed = time.time() - started

    assert elapsed < 5, f"connect did not time out (took {elapsed:.1f}s)"
    assert client in manager.removed
    assert client.socket is None
    server.close()
