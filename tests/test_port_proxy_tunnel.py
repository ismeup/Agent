import base64
import json
import socket
import threading
import time

import pytest
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

from agent.models.port_proxy_check import PortProxyCheck
from agent.operation_controller.models import Operations
from agent.operation_controller.operation_controller import OperationController
from agent.port_proxy.tunnel import PortProxyTunnel

_PROXY_PRIVATE_KEY = RSA.generate(2048)
PROXY_PUBLIC_KEY_B64 = base64.b64encode(_PROXY_PRIVATE_KEY.publickey().export_key(format="DER")).decode()


def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


class MockProxy:

    def __init__(self):
        self.private_key = _PROXY_PRIVATE_KEY
        self.public_key_b64 = PROXY_PUBLIC_KEY_B64
        self.uid = "uid-test"
        self.sid = "sid-test"
        self.agent_port = 0
        self.external_port = 0
        self.aes_key_bytes = None
        self.agent_sock = None
        self.client_sock = None
        self.send_lock = threading.Lock()
        self.opened_event = threading.Event()
        self.imok_event = threading.Event()
        self.agent_close_event = threading.Event()
        self.closed = False
        self.agent_server = None
        self.external_server = None
        self.ready_event = threading.Event()
        self.handshake_ok = threading.Event()

    # ---------- crypto ----------
    def _make_aes(self, aes_key: str):
        self.aes_key_bytes = SHA1.new(aes_key.encode("utf-8")).digest()[:16]

    def _encrypt(self, data: bytes) -> bytes:
        c = AES.new(self.aes_key_bytes, AES.MODE_ECB)
        return c.encrypt(pad(data, AES.block_size, style="pkcs7"))

    def _decrypt(self, data: bytes) -> bytes:
        c = AES.new(self.aes_key_bytes, AES.MODE_ECB)
        return unpad(c.decrypt(data), AES.block_size, style="pkcs7")

    # ---------- framing ----------
    def _send_frame(self, sock, data: bytes):
        with self.send_lock:
            if self.closed or sock is None:
                return
            try:
                sock.sendall(f"len:{len(data)}:".encode("utf-8"))
                sock.sendall(b"\x00")
                sock.sendall(data)
            except OSError:
                pass

    def _read_frame(self, sock) -> bytes:
        header = bytearray()
        while True:
            b = sock.recv(1)
            if not b:
                raise ConnectionError("closed")
            if b[0] == 0:
                break
            header.append(b[0])
        ls = header.decode("utf-8", errors="ignore")
        start = ls.index("len:") + 4
        end = ls.rindex(":")
        length = int(ls[start:end])
        data = bytearray()
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data.extend(chunk)
        return bytes(data)

    # ---------- protocol ----------
    def _send_control(self, obj: dict):
        self._send_frame(self.agent_sock, self._encrypt(b"\x01" + json.dumps(obj).encode()))

    def _send_data(self, sid: str, data: bytes):
        sb = sid.encode()
        body = len(sb).to_bytes(2, "big") + sb + data
        self._send_frame(self.agent_sock, self._encrypt(b"\x02" + body))

    # ---------- lifecycle ----------
    def run(self):
        self.agent_server = socket.socket()
        self.agent_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.agent_server.bind(("127.0.0.1", 0))
        self.agent_port = self.agent_server.getsockname()[1]
        self.agent_server.listen(1)
        self.external_server = socket.socket()
        self.external_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.external_server.bind(("127.0.0.1", 0))
        self.external_port = self.external_server.getsockname()[1]
        self.external_server.listen(1)
        self.ready_event.set()

        self.agent_sock, _ = self.agent_server.accept()
        self.agent_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Handshake
        frame = self._read_frame(self.agent_sock)
        cipher = PKCS1_v1_5.new(self.private_key)
        decrypted = cipher.decrypt(frame, None)
        if decrypted is None:
            raise ValueError("RSA handshake decrypt failed")
        handshake = json.loads(decrypted.decode())
        self._make_aes(handshake["aes"])
        self.uid = handshake["uid"]
        self._send_frame(self.agent_sock, self._encrypt(("HELLO:" + self.uid).encode()))
        self.handshake_ok.set()

        threading.Thread(target=self._accept_client_and_open, daemon=True).start()
        self._agent_reader_loop()

    def _accept_client_and_open(self):
        self.client_sock, _ = self.external_server.accept()
        self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._send_control({"t": "open", "sid": self.sid})
        # forward client -> agent
        try:
            while not self.closed:
                data = self.client_sock.recv(8192)
                if not data:
                    break
                self._send_data(self.sid, data)
            if not self.closed:
                self._send_control({"t": "close", "sid": self.sid})
        except OSError:
            pass

    def _agent_reader_loop(self):
        try:
            while not self.closed:
                frame = self._read_frame(self.agent_sock)
                plain = self._decrypt(frame)
                mtype = plain[0]
                if mtype == 0x01:
                    obj = json.loads(plain[1:].decode())
                    t = obj.get("t")
                    if t == "open_ok":
                        self.opened_event.set()
                    elif t == "IMOK":
                        self.imok_event.set()
                    elif t == "close":
                        self.agent_close_event.set()
                        break
                elif mtype == 0x02:
                    body = plain[1:]
                    sl = int.from_bytes(body[:2], "big")
                    data = body[2 + sl:]
                    if self.client_sock is not None:
                        self.client_sock.sendall(data)
        except (OSError, ConnectionError):
            pass
        finally:
            self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        for s in (self.agent_sock, self.client_sock, self.agent_server, self.external_server):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def start_echo_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(1)

    def run():
        try:
            conn, _ = server.accept()
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                data = conn.recv(65535)
                if not data:
                    break
                conn.sendall(data)
            conn.close()
        except OSError:
            pass

    threading.Thread(target=run, daemon=True).start()
    return server, port


def start_udp_echo_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def run():
        while True:
            try:
                data, addr = server.recvfrom(65535)
            except OSError:
                break
            server.sendto(data, addr)

    threading.Thread(target=run, daemon=True).start()
    return server, port


def start_multi_echo_server():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(5)

    def handle(conn):
        try:
            while True:
                data = conn.recv(65535)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def run():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                break
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=run, daemon=True).start()
    return server, port


# ---------- tests ----------

def test_operation_controller_maps_port_proxy():
    op_type, checker = OperationController().create_operation({"operation": "port_proxy"})
    assert op_type == Operations.PORT_PROXY
    assert isinstance(checker, PortProxyCheck)


def test_operation_controller_maps_port_proxy_close():
    op_type, checker = OperationController().create_operation({"operation": "port_proxy_close"})
    assert op_type == Operations.PORT_PROXY_CLOSE
    from agent.models.port_proxy_close import PortProxyCloseCheck
    assert isinstance(checker, PortProxyCloseCheck)


def test_close_stops_active_tunnel():
    from agent.models.port_proxy_close import PortProxyCloseCheck
    from agent.port_proxy.tunnel import get_tunnel

    holder, port = _connection_holder()
    tunnel = PortProxyTunnel("close-uid", "127.0.0.1", port, PROXY_PUBLIC_KEY_B64,
                             {"host": "127.0.0.1", "port": 1, "protocol": "tcp"})
    tunnel.start()
    deadline = time.time() + 5
    while time.time() < deadline and tunnel.socket is None:
        time.sleep(0.02)
    assert tunnel.socket is not None and not tunnel.closed
    assert get_tunnel("close-uid") is tunnel

    checker = PortProxyCloseCheck()
    checker.run_check({"uid": "close-uid"})
    result = checker.get_operation_result()
    assert result["status"] is True

    assert tunnel.closed
    checker2 = PortProxyCloseCheck()
    checker2.run_check({"uid": "close-uid"})
    assert checker2.get_operation_result()["status"] is True

    holder.close()


def test_checker_missing_params():
    checker = PortProxyCheck()
    checker.run_check({"uid": "", "proxy_ip": "", "proxy_port": 0, "proxy_public_key": ""})
    result = checker.get_operation_result()
    assert result["status"] is False
    assert "error" in result


def test_tcp_tunnel_echo():
    target_server, target_port = start_echo_server()
    proxy = MockProxy()
    threading.Thread(target=proxy.run, daemon=True).start()
    assert proxy.ready_event.wait(timeout=5)

    tunnel = PortProxyTunnel(
        "uid-test", "127.0.0.1", proxy.agent_port, proxy.public_key_b64,
        {"host": "127.0.0.1", "port": target_port, "protocol": "tcp"},
    )
    tunnel.start()

    client = socket.create_connection(("127.0.0.1", proxy.external_port), timeout=5)
    assert proxy.opened_event.wait(timeout=5), "agent did not open stream"

    client.sendall(b"ping")
    assert recv_exact(client, 4) == b"ping"

    big = bytes(range(256)) * 400  # 102400 bytes
    client.sendall(big)
    assert recv_exact(client, len(big)) == big

    client.close()
    tunnel.stop()
    proxy.close()
    target_server.close()


def test_keepalive_imok():
    target_server, target_port = start_echo_server()
    proxy = MockProxy()
    threading.Thread(target=proxy.run, daemon=True).start()
    assert proxy.ready_event.wait(timeout=5)

    tunnel = PortProxyTunnel(
        "uid-test", "127.0.0.1", proxy.agent_port, proxy.public_key_b64,
        {"host": "127.0.0.1", "port": target_port, "protocol": "tcp"},
    )
    tunnel.start()

    client = socket.create_connection(("127.0.0.1", proxy.external_port), timeout=5)
    assert proxy.opened_event.wait(timeout=5)

    proxy._send_control({"t": "AREYOUOK"})
    assert proxy.imok_event.wait(timeout=5), "agent did not reply IMOK"

    client.close()
    tunnel.stop()
    proxy.close()
    target_server.close()


def test_close_propagation():
    target_server, target_port = start_echo_server()
    proxy = MockProxy()
    threading.Thread(target=proxy.run, daemon=True).start()
    assert proxy.ready_event.wait(timeout=5)

    tunnel = PortProxyTunnel(
        "uid-test", "127.0.0.1", proxy.agent_port, proxy.public_key_b64,
        {"host": "127.0.0.1", "port": target_port, "protocol": "tcp"},
    )
    tunnel.start()

    client = socket.create_connection(("127.0.0.1", proxy.external_port), timeout=5)
    assert proxy.opened_event.wait(timeout=5)

    client.sendall(b"hi")
    assert recv_exact(client, 2) == b"hi"

    client.close()
    deadline = time.time() + 5
    target_closed = False
    while time.time() < deadline:
        if not tunnel.targets:
            target_closed = True
            break
        time.sleep(0.05)
    assert target_closed, "agent did not close the target stream"

    tunnel.stop()
    proxy.close()
    target_server.close()


def _connection_holder():
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(5)
    accepted: list[socket.socket] = []

    def run():
        while True:
            try:
                c, _ = server.accept()
                c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                accepted.append(c)
            except OSError:
                break

    threading.Thread(target=run, daemon=True).start()
    return server, port


def test_register_tunnel_replaces_same_uid():
    holder, port = _connection_holder()

    t1 = PortProxyTunnel("dup-uid", "127.0.0.1", port, PROXY_PUBLIC_KEY_B64,
                         {"host": "127.0.0.1", "port": 1, "protocol": "tcp"})
    t1.start()
    deadline = time.time() + 5
    while time.time() < deadline and t1.socket is None:
        time.sleep(0.02)
    assert t1.socket is not None and not t1.closed

    t2 = PortProxyTunnel("dup-uid", "127.0.0.1", port, PROXY_PUBLIC_KEY_B64,
                         {"host": "127.0.0.1", "port": 1, "protocol": "tcp"})
    t2.start()
    assert t1.closed, "old tunnel with same uid was not stopped"

    t2.stop()
    holder.close()


def test_stop_all_tunnels_stops_everything():
    from agent.port_proxy import tunnel as tunnel_module

    holder, port = _connection_holder()
    t1 = PortProxyTunnel("all-1", "127.0.0.1", port, PROXY_PUBLIC_KEY_B64,
                         {"host": "127.0.0.1", "port": 1, "protocol": "tcp"})
    t2 = PortProxyTunnel("all-2", "127.0.0.1", port, PROXY_PUBLIC_KEY_B64,
                         {"host": "127.0.0.1", "port": 1, "protocol": "tcp"})
    t1.start()
    t2.start()
    deadline = time.time() + 5
    while time.time() < deadline and (t1.socket is None or t2.socket is None):
        time.sleep(0.02)
    assert t1.socket is not None and t2.socket is not None
    assert tunnel_module.get_tunnel("all-1") is t1
    assert tunnel_module.get_tunnel("all-2") is t2

    tunnel_module.stop_all_tunnels()

    assert t1.closed
    assert t2.closed
    assert tunnel_module.get_tunnel("all-1") is None
    assert tunnel_module.get_tunnel("all-2") is None
    holder.close()


def test_remove_thread_stops_tunnels_on_full_loss(monkeypatch):
    import agent.client.client_manager as cm_module
    from agent.client.client_manager import ClientManager
    from agent.port_proxy import tunnel as tunnel_module

    monkeypatch.setattr(cm_module.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(ClientManager, "start", lambda self: None)

    manager = object.__new__(ClientManager)
    manager.remote_clients = []
    manager.threads_requested = 0
    manager.list_synchronizer = threading.Lock()

    holder, port = _connection_holder()
    t1 = PortProxyTunnel("loss-1", "127.0.0.1", port, PROXY_PUBLIC_KEY_B64,
                         {"host": "127.0.0.1", "port": 1, "protocol": "tcp"})
    t2 = PortProxyTunnel("loss-2", "127.0.0.1", port, PROXY_PUBLIC_KEY_B64,
                         {"host": "127.0.0.1", "port": 1, "protocol": "tcp"})
    t1.start()
    t2.start()
    deadline = time.time() + 5
    while time.time() < deadline and (t1.socket is None or t2.socket is None):
        time.sleep(0.02)
    assert t1.socket is not None and t2.socket is not None

    fake_client = object()
    manager.add_thread(fake_client)
    assert tunnel_module.get_tunnel("loss-1") is t1

    manager.remove_thread(fake_client)

    assert t1.closed
    assert t2.closed
    assert tunnel_module.get_tunnel("loss-1") is None
    assert tunnel_module.get_tunnel("loss-2") is None
    holder.close()


def test_remove_thread_keeps_tunnels_when_some_remain(monkeypatch):
    import agent.client.client_manager as cm_module
    from agent.client.client_manager import ClientManager

    monkeypatch.setattr(cm_module.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(ClientManager, "start", lambda self: None)

    manager = object.__new__(ClientManager)
    manager.remote_clients = []
    manager.threads_requested = 0
    manager.list_synchronizer = threading.Lock()

    holder, port = _connection_holder()
    t1 = PortProxyTunnel("keep-1", "127.0.0.1", port, PROXY_PUBLIC_KEY_B64,
                         {"host": "127.0.0.1", "port": 1, "protocol": "tcp"})
    t1.start()
    deadline = time.time() + 5
    while time.time() < deadline and t1.socket is None:
        time.sleep(0.02)
    assert t1.socket is not None

    c1, c2 = object(), object()
    manager.add_thread(c1)
    manager.add_thread(c2)
    manager.remove_thread(c1)

    assert not t1.closed
    t1.stop()
    holder.close()


def test_udp_echo_source_filter_and_idle_close():
    target_server, target_port = start_udp_echo_server()
    proxy = MockProxy()
    threading.Thread(target=proxy.run, daemon=True).start()
    assert proxy.ready_event.wait(timeout=5)

    tunnel = PortProxyTunnel(
        "uid-udp", "127.0.0.1", proxy.agent_port, proxy.public_key_b64,
        {"host": "127.0.0.1", "port": target_port, "protocol": "udp"},
        udp_idle_timeout=1,
    )
    tunnel.start()

    client = socket.create_connection(("127.0.0.1", proxy.external_port), timeout=5)
    assert proxy.opened_event.wait(timeout=5), "agent did not open stream"

    client.sendall(b"ping")
    assert recv_exact(client, 4) == b"ping"

    agent_sock = tunnel.targets["sid-test"]
    attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    attacker.sendto(b"evil", agent_sock.getsockname())
    client.sendall(b"ok")
    assert recv_exact(client, 2) == b"ok", "foreign datagram was injected into the stream"

    assert proxy.agent_close_event.wait(timeout=10), "agent did not close the idle udp stream"

    client.close()
    tunnel.stop()
    proxy.close()
    target_server.close()
    attacker.close()


def test_reopen_same_sid_replaces_stream():
    target_server, target_port = start_multi_echo_server()
    proxy = MockProxy()
    threading.Thread(target=proxy.run, daemon=True).start()
    assert proxy.ready_event.wait(timeout=5)

    tunnel = PortProxyTunnel(
        "uid-reopen", "127.0.0.1", proxy.agent_port, proxy.public_key_b64,
        {"host": "127.0.0.1", "port": target_port, "protocol": "tcp"},
    )
    tunnel.start()

    client = socket.create_connection(("127.0.0.1", proxy.external_port), timeout=5)
    assert proxy.opened_event.wait(timeout=5), "agent did not open stream"

    client.sendall(b"one")
    assert recv_exact(client, 3) == b"one"

    old_target = tunnel.targets["sid-test"]

    proxy._send_control({"t": "open", "sid": proxy.sid})
    new_target = None
    deadline = time.time() + 5
    while time.time() < deadline:
        candidate = tunnel.targets.get("sid-test")
        if candidate is not None and candidate is not old_target:
            new_target = candidate
            break
        time.sleep(0.02)
    assert new_target is not None, "stream was not replaced on re-open"
    assert old_target.fileno() == -1, "old target socket was not closed (leak)"

    client.sendall(b"two")
    assert recv_exact(client, 3) == b"two"
    assert tunnel.targets.get("sid-test") is new_target, "new stream was killed by old relay"

    client.close()
    tunnel.stop()
    proxy.close()
    target_server.close()
