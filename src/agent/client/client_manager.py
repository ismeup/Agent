import threading
import time
import traceback
from typing import List
from agent.client.connection_data import ConnectionData
from Crypto.Cipher import PKCS1_v1_5

from agent.client.remote_client import RemoteClient


def _safe_print(message: str) -> None:
    try:
        print(message)
    except Exception:
        pass


class ClientManager:
    def __init__(self, connection_data: ConnectionData, identity: str, rsa_cipher: PKCS1_v1_5.PKCS115_Cipher):
        self.remote_clients: List['RemoteClient'] = []
        self.connection_data = connection_data
        self.identity = identity
        self.rsa_cipher = rsa_cipher
        self.list_synchronizer = threading.Lock()
        self.threads_requested = 0

        self.start()
        try:
            threading.Thread(target=self._disconnect_by_keep_alive_timeout, daemon=True).start()
        except Exception as e:
            _safe_print(f"### Failed to start keep-alive thread: {e!r}")

    def start(self):
        from agent.client.remote_client import RemoteClient
        while True:
            try:
                main_client = RemoteClient(self, self.connection_data, self.identity, self.rsa_cipher)
                threading.Thread(target=main_client.run).start()
                return
            except Exception as e:
                _safe_print(f"### Failed to start client thread: {e!r}. Retrying in 5 seconds")
                time.sleep(5)

    def add_thread(self, remote_client):
        with self.list_synchronizer:
            self.remote_clients.append(remote_client)
            self._print_threads_count()

    def _print_threads_count(self):
        _safe_print(f"### Current thread count: {len(self.remote_clients)}")

    def remove_thread(self, remote_client):
        should_reconnect = False
        with self.list_synchronizer:
            if remote_client in self.remote_clients:
                self.remote_clients.remove(remote_client)
            self.threads_requested = max(0, self.threads_requested - 1)

            if len(self.remote_clients) == 0:
                should_reconnect = True

        if should_reconnect:
            self._stop_port_proxy_tunnels()
            _safe_print("### No threads online. Reconnecting in 5 seconds")
            time.sleep(5)
            self.start()

    def _stop_port_proxy_tunnels(self):
        try:
            from agent.port_proxy.tunnel import stop_all_tunnels
            stop_all_tunnels()
        except Exception as e:
            _safe_print(f"### Failed to stop port-proxy tunnels on Worker disconnect: {e}")

    def request_threads(self, count: int):
        from agent.client.remote_client import RemoteClient
        with self.list_synchronizer:
            if count != self.threads_requested:
                self.threads_requested = count
                current_size = len(self.remote_clients)
                if current_size < count:
                    _safe_print(f"### Server requested more threads. Current count is {current_size}; Requested: {count}")
                    for _ in range(current_size, count):
                        client = RemoteClient(self, self.connection_data, self.identity, self.rsa_cipher)
                        try:
                            threading.Thread(target=client.run).start()
                        except Exception as e:
                            self.threads_requested = max(0, self.threads_requested - 1)
                            _safe_print(f"### Failed to start additional thread: {e!r}")

    def get_thread_id(self, remote_client) -> str:
        try:
            return str(self.remote_clients.index(remote_client))
        except ValueError:
            return "-1"

    def _disconnect_by_keep_alive_timeout(self):
        ticks = 0
        while True:
            try:
                with self.list_synchronizer:
                    for remote_client in list(self.remote_clients):
                        remote_client.disconnect_by_keep_alive()
            except Exception:
                try:
                    traceback.print_exc()
                except Exception:
                    pass
            time.sleep(5)
            ticks += 1
            if ticks % 12 == 0:
                _safe_print(f"### Agent alive. Active threads: {threading.active_count()}")
