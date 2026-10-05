import base64
import json
import queue
import socket
import threading
from datetime import datetime
from typing import Optional

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from agent import protocol

TARGET_CONNECT_TIMEOUT = 10
MAX_STREAMS = 16
READY_TIMEOUT = protocol.CONNECT_TIMEOUT_SECONDS + 20
UDP_IDLE_TIMEOUT = 60
SEND_QUEUE_CAPACITY = 16
TARGET_WRITE_TIMEOUT = 120

_QUEUE_EOF = object()

_active_tunnels: dict[str, "PortProxyTunnel"] = {}
_tunnel_lock = threading.Lock()


def register_tunnel(uid: str, tunnel: "PortProxyTunnel") -> None:
    with _tunnel_lock:
        old = _active_tunnels.get(uid)
        _active_tunnels[uid] = tunnel
    if old is not None and old is not tunnel:
        old.stop()


def unregister_tunnel(uid: str, tunnel: "PortProxyTunnel") -> None:
    with _tunnel_lock:
        if _active_tunnels.get(uid) is tunnel:
            _active_tunnels.pop(uid, None)


def get_tunnel(uid: str) -> Optional["PortProxyTunnel"]:
    with _tunnel_lock:
        return _active_tunnels.get(uid)


def stop_all_tunnels() -> None:
    with _tunnel_lock:
        tunnels = list(_active_tunnels.values())
        _active_tunnels.clear()
    for t in tunnels:
        t.stop()


class TargetStream:

    __slots__ = ("target", "send_queue", "open")

    def __init__(self, target: socket.socket):
        self.target = target
        self.send_queue = queue.Queue(maxsize=SEND_QUEUE_CAPACITY)
        self.open = True


class PortProxyTunnel:

    def __init__(self, uid: str, proxy_host: str, proxy_port: int,
                  proxy_public_key_b64: str, routing: dict,
                  udp_idle_timeout: float = UDP_IDLE_TIMEOUT,
                  max_streams: int = MAX_STREAMS):
        self.uid = uid
        self.proxy_host = proxy_host
        self.proxy_port = int(proxy_port)
        self.proxy_public_key_b64 = proxy_public_key_b64
        self.routing = routing or {}
        self.target_host = str(self.routing.get("host", ""))
        self.target_port = int(self.routing.get("port", 0))
        self.protocol = str(self.routing.get("protocol") or "tcp").lower()
        self.udp_idle_timeout = udp_idle_timeout
        self.max_streams = int(max_streams)

        self.socket: Optional[socket.socket] = None
        self.send_lock = threading.Lock()
        self.targets_lock = threading.Lock()
        self.targets: dict[str, TargetStream] = {}
        self.closed = False
        self.ready_event = threading.Event()
        self.aes_key_bytes: Optional[bytes] = None
        self.rsa_cipher: Optional[PKCS1_v1_5.PKCS115_Cipher] = None
        self.thread: Optional[threading.Thread] = None
        self.error: str = ""

    # ---------- public ----------
    def start(self) -> None:
        register_tunnel(self.uid, self)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.closed = True
        self._close_socket(self.socket)
        with self.targets_lock:
            streams = list(self.targets.values())
            self.targets.clear()
        for stream in streams:
            self._close_stream_state(stream)

    def wait_ready(self, timeout: float) -> bool:
        return self.ready_event.wait(timeout) and self.error == "" and not self.closed

    # ---------- protocol helpers ----------
    def _send_encrypted(self, body: bytes) -> None:
        if self.closed or self.socket is None:
            return
        try:
            protocol.write_frame(self.socket, protocol.aes_encrypt(self.aes_key_bytes, body), self.send_lock)
        except OSError:
            self.stop()

    def _send_control(self, obj: dict) -> None:
        self._send_encrypted(b"\x01" + json.dumps(obj).encode("utf-8"))

    def _send_data(self, sid: str, data: bytes) -> None:
        sid_bytes = sid.encode("utf-8")
        body = len(sid_bytes).to_bytes(2, "big") + sid_bytes + data
        self._send_encrypted(b"\x02" + body)

    # ---------- run ----------
    def _run(self) -> None:
        try:
            pubkey = RSA.import_key(base64.b64decode(self.proxy_public_key_b64))
            self.rsa_cipher = PKCS1_v1_5.new(pubkey)

            self.socket = protocol.connect_tcp(
                self.proxy_host, self.proxy_port,
                nodelay=True, timeout=protocol.CONNECT_TIMEOUT_SECONDS,
            )

            aes_key = protocol.generate_aes_key()
            hello, self.aes_key_bytes = protocol.perform_handshake(
                self.socket, self.rsa_cipher,
                {"uid": self.uid, "aes": aes_key, "version": 1},
                aes_key,
            )
            if not hello.startswith("HELLO:"):
                raise ConnectionError("handshake failed: " + hello)

            self.socket.settimeout(None)
            self.ready_event.set()

            self._reader_loop()
        except Exception as e:
            self.error = str(e)
            if not self.closed:
                print(f"{datetime.now()} [port_proxy] tunnel {self.uid} error: {e}")
        finally:
            self.ready_event.set()
            self.stop()
            unregister_tunnel(self.uid, self)

    def _reader_loop(self) -> None:
        while not self.closed:
            frame = protocol.read_frame(self.socket, max_bytes=protocol.MAX_FRAME_BYTES)
            plain = protocol.aes_decrypt(self.aes_key_bytes, frame)
            mtype = plain[0]
            if mtype == 0x01:
                obj = json.loads(plain[1:].decode("utf-8"))
                self._handle_control(obj)
            elif mtype == 0x02:
                self._handle_data(plain[1:])

    def _handle_control(self, obj: dict) -> None:
        t = obj.get("t", "")
        if t == "open":
            self._open_stream(obj.get("sid", ""))
        elif t == "close":
            self._close_stream(obj.get("sid", ""))
        elif t == "AREYOUOK":
            self._send_control({"t": "IMOK"})

    def _open_stream(self, sid: str) -> None:
        with self.targets_lock:
            if sid not in self.targets and len(self.targets) >= self.max_streams:
                self._send_control({"t": "open_err", "sid": sid, "err": "max streams reached"})
                return
        try:
            if self.protocol == "udp":
                target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                target.connect((self.target_host, self.target_port))
                target.settimeout(self.udp_idle_timeout)
            else:
                target = socket.create_connection(
                    (self.target_host, self.target_port),
                    timeout=TARGET_CONNECT_TIMEOUT,
                )
                target.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                target.settimeout(TARGET_WRITE_TIMEOUT)
            stream = TargetStream(target)
            with self.targets_lock:
                old = self.targets.pop(sid, None)
                self.targets[sid] = stream
            if old is not None:
                self._close_stream_state(old)
            self._send_control({"t": "open_ok", "sid": sid})
            threading.Thread(target=self._relay_target_to_proxy, args=(sid, stream), daemon=True).start()
            if self.protocol != "udp":
                threading.Thread(target=self._relay_proxy_to_target, args=(sid, stream), daemon=True).start()
        except Exception as e:
            self._send_control({"t": "open_err", "sid": sid, "err": str(e)})

    def _close_stream(self, sid: str) -> None:
        with self.targets_lock:
            stream = self.targets.pop(sid, None)
        if stream is not None:
            self._close_stream_state(stream)

    def _relay_target_to_proxy(self, sid: str, stream: TargetStream) -> None:
        target = stream.target
        target_eof = False
        try:
            if self.protocol == "udp":
                while not self.closed and stream.open:
                    try:
                        data = target.recv(65535)
                    except socket.timeout:
                        target_eof = True
                        break
                    except OSError:
                        break
                    if self.closed or not stream.open:
                        break
                    self._send_data(sid, data)
            else:
                while not self.closed and stream.open:
                    try:
                        chunk = target.recv(8192)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not chunk:
                        target_eof = True
                        break
                    self._send_data(sid, chunk)
        finally:
            stream.open = False
            with self.targets_lock:
                owned = self.targets.get(sid) is stream
                if owned:
                    self.targets.pop(sid, None)
            self._close_socket(target)
            if owned and target_eof and not self.closed:
                self._send_control({"t": "close", "sid": sid})

    def _relay_proxy_to_target(self, sid: str, stream: TargetStream) -> None:
        try:
            while not self.closed and stream.open:
                item = stream.send_queue.get()
                if item is _QUEUE_EOF:
                    break
                if self.closed or not stream.open:
                    break
                try:
                    stream.target.sendall(item)
                except OSError:
                    break
        finally:
            self._kill_stream(sid, stream)

    def _kill_stream(self, sid: str, stream: TargetStream) -> None:
        stream.open = False
        with self.targets_lock:
            owned = self.targets.get(sid) is stream
            if owned:
                self.targets.pop(sid, None)
        self._close_stream_state(stream)
        if owned and not self.closed:
            self._send_control({"t": "close", "sid": sid})

    def _close_stream_state(self, stream: TargetStream) -> None:
        stream.open = False
        try:
            stream.send_queue.put_nowait(_QUEUE_EOF)
        except queue.Full:
            pass
        self._close_socket(stream.target)

    def _handle_data(self, body: bytes) -> None:
        sid_len = int.from_bytes(body[:2], "big")
        sid = body[2:2 + sid_len].decode("utf-8")
        data = body[2 + sid_len:]
        with self.targets_lock:
            stream = self.targets.get(sid)
        if stream is None or not stream.open:
            return
        try:
            if self.protocol == "udp":
                stream.target.send(data)
            else:
                stream.send_queue.put_nowait(data)
        except queue.Full:
            self._kill_stream(sid, stream)
        except OSError:
            self._kill_stream(sid, stream)

    @staticmethod
    def _close_socket(sock) -> None:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
