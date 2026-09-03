import json
import socket
import threading
import time
import uuid
from datetime import datetime

from agent import protocol
from agent.config import AGENT_VERSION
from agent.exceptions import RemoteConnectException
from agent.operation_controller.operation_controller import OperationController

class RemoteClient:
    def __init__(self, client_manager, connection_data, identity, rsa_cipher):
        self.client_manager = client_manager
        self.connection_data = connection_data
        self.identity = identity
        self.rsa_cipher = rsa_cipher

        self.socket = None
        self.synchronizer = threading.Lock()
        self.last_success_packet = 0
        self.ready = False
        self.aes_key = None
        self.aes_key_bytes = None

    def connect(self):
        try:
            self.socket = protocol.connect_tcp(
                self.connection_data.get_host(), self.connection_data.get_port()
            )

            self.aes_key = protocol.generate_aes_key()
            hello, self.aes_key_bytes = protocol.perform_handshake(
                self.socket, self.rsa_cipher,
                {"iam": self.identity, "aes": self.aes_key, "version": AGENT_VERSION},
                self.aes_key,
            )
            if hello != f"HELLO{self.identity}":
                raise RemoteConnectException("unexpected handshake: " + hello)

            self.ready = True
            self.update_keep_alive()
            self.read_messages()
        except Exception:
            self.disconnect()
            raise RemoteConnectException()

    def disconnect(self):
        self.ready = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None

    def print_thread(self, message: str):
        print(f"{datetime.now()} TH {self.client_manager.get_thread_id(self)} : {message}")

    def disconnect_by_keep_alive(self):
        if self.ready and (time.time() * 1000 - self.last_success_packet) > 60000:
            self.print_thread("Disconnecting by keep-alive timeout")
            self.disconnect()

    def update_keep_alive(self):
        self.print_thread("Updating keep-alive")
        self.last_success_packet = time.time() * 1000

    def read_messages(self):
        while self.socket:
            try:
                frame = protocol.read_frame(self.socket, max_bytes=None)
            except (protocol.FrameError, OSError):
                self.disconnect()
                break
            self.parse_message(frame)

    def send_bytes(self, data_bytes: bytes):
        self.print_thread(f">>>>>>> {data_bytes.decode('utf-8', errors='ignore')}")
        try:
            encrypted = protocol.aes_encrypt(self.aes_key_bytes, data_bytes)
            protocol.write_frame(self.socket, encrypted, self.synchronizer)
        except Exception:
            self.disconnect()

    def parse_message(self, message_data: bytes):
        try:
            message = protocol.aes_decrypt(self.aes_key_bytes, message_data).decode('utf-8')
            self.print_thread(f"<<<<<<< {message}")

            if not self.ready and message == f"HELLO{self.identity}":
                self.update_keep_alive()
                self.ready = True
                return

            if self.ready:
                if message.startswith("THREADS: "):
                    try:
                        threads_count = int(message.replace("THREADS: ", ""))
                        if 0 < threads_count < 64:
                            self.client_manager.request_threads(threads_count)
                    except Exception:
                        self.disconnect()

                elif message == "AREYOUOK":
                    self.update_keep_alive()
                    self.send_bytes(b"IMOK")
                    return

                elif message.startswith("message "):
                    try:
                        start = message.index(" ")
                        end = message.index(":")
                        uuid_str = message[start + 1:end]
                        task_uuid = uuid.UUID(uuid_str)
                        json_str = message[end + 1:]

                        json_object = json.loads(json_str)

                        def run_task():
                            controller = OperationController()
                            result = controller.start_check(json_object)
                            self.send_answer(json.dumps(result), task_uuid)
                            self.update_keep_alive()

                        threading.Thread(target=run_task, daemon=True).start()
                    except Exception:
                        self.disconnect()
                    return
        except Exception:
            self.disconnect()

    def send_answer(self, message: str, task_id: uuid.UUID):
        answer_message = f"answer {task_id}: {message}"
        self.send_bytes(answer_message.encode('utf-8'))

    def run(self):
        self.client_manager.add_thread(self)
        self.print_thread(f"Connecting to server {self.connection_data.get_host()}:{self.connection_data.get_port()}...")
        try:
            self.connect()
        except RemoteConnectException:
            self.print_thread("Connection aborted!")

        self.print_thread("Closing connection\n")
        self.client_manager.remove_thread(self)
