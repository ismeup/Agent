import time
import threading
from typing import List
from agent.client.connection_data import ConnectionData
from Crypto.Cipher import PKCS1_v1_5

from agent.client.remote_client import RemoteClient


class ClientManager:
    def __init__(self, connection_data: ConnectionData, identity: str, rsa_cipher: PKCS1_v1_5.PKCS115_Cipher):
        self.remote_clients: List['RemoteClient'] = []
        self.connection_data = connection_data
        self.identity = identity
        self.rsa_cipher = rsa_cipher
        self.list_synchronizer = threading.Lock()
        self.threads_requested = 0

        self.start()
        threading.Thread(target=self._disconnect_by_keep_alive_timeout, daemon=True).start()

    def start(self):
        from agent.client.remote_client import RemoteClient
        main_client = RemoteClient(self, self.connection_data, self.identity, self.rsa_cipher)
        threading.Thread(target=main_client.run).start()

    def add_thread(self, remote_client):
        with self.list_synchronizer:
            self.remote_clients.append(remote_client)
            self._print_threads_count()

    def _print_threads_count(self):
        print(f"### Current thread count: {len(self.remote_clients)}")

    def remove_thread(self, remote_client):
        should_reconnect = False
        with self.list_synchronizer:
            if remote_client in self.remote_clients:
                self.remote_clients.remove(remote_client)
            self.threads_requested = max(0, self.threads_requested - 1)

            if len(self.remote_clients) == 0:
                should_reconnect = True

        if should_reconnect:
            print("### No threads online. Reconnecting in 5 seconds")
            time.sleep(5)
            self.start()

    def request_threads(self, count: int):
        from agent.client.remote_client import RemoteClient
        with self.list_synchronizer:
            if count != self.threads_requested:
                self.threads_requested = count
                current_size = len(self.remote_clients)
                if current_size < count:
                    print(f"### Server requested more threads. Current count is {current_size}; Requested: {count}")
                    for _ in range(current_size, count):
                        client = RemoteClient(self, self.connection_data, self.identity, self.rsa_cipher)
                        threading.Thread(target=client.run).start()

    def get_thread_id(self, remote_client) -> str:
        try:
            return str(self.remote_clients.index(remote_client))
        except ValueError:
            return "-1"

    def _disconnect_by_keep_alive_timeout(self):
        while True:
            with self.list_synchronizer:
                for remote_client in list(self.remote_clients):
                    remote_client.disconnect_by_keep_alive()
            time.sleep(5)
