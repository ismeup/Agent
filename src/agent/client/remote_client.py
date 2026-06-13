import socket
import json
import uuid
import threading
import time
from datetime import datetime

from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad

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
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'TCP_KEEPIDLE'):
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            if hasattr(socket, 'TCP_KEEPINTVL'):
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            if hasattr(socket, 'TCP_KEEPCNT'):
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            self.socket.connect((self.connection_data.get_host(), self.connection_data.get_port()))
            
            if self._configure_ciphers():
                self.negotiate()
                self.read_messages()
        except Exception:
            raise RemoteConnectException()

    def _configure_ciphers(self) -> bool:
        try:
            self.aes_key = str(uuid.uuid4())
            sha = SHA1.new(self.aes_key.encode('utf-8'))
            self.aes_key_bytes = sha.digest()[:16]
            return True
        except Exception:
            self.disconnect()
            return False

    def _encrypt_aes(self, data: bytes) -> bytes:
        cipher = AES.new(self.aes_key_bytes, AES.MODE_ECB)
        return cipher.encrypt(pad(data, AES.block_size, style='pkcs7'))

    def _decrypt_aes(self, data: bytes) -> bytes:
        cipher = AES.new(self.aes_key_bytes, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), AES.block_size, style='pkcs7')

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

    def negotiate(self):
        payload = {"iam": self.identity, "aes": self.aes_key}
        message_bytes = json.dumps(payload).encode('utf-8')
        encrypted_data = self.rsa_cipher.encrypt(message_bytes)
        self.send_bytes_raw(encrypted_data)
        self.update_keep_alive()

    def read_messages(self):
        buffer = bytearray()
        while self.socket:
            try:
                chunk = self.socket.recv(1)
                if not chunk:
                    self.disconnect()
                    break
                
                b = chunk[0]
                if b == 0:
                    length = self._parse_length(buffer.decode('utf-8', errors='ignore'))
                    buffer.clear()
                    
                    data = bytearray()
                    while len(data) < length:
                        packet = self.socket.recv(length - len(data))
                        if not packet:
                            break
                        data.extend(packet)
                        
                    if len(data) == length:
                        self.parse_message(bytes(data))
                else:
                    buffer.append(b)
            except Exception:
                self.disconnect()
                break

    def _parse_length(self, length_str: str) -> int:
        if "len:" in length_str:
            try:
                end = length_str.rindex(":")
                return int(length_str[4:end])
            except Exception:
                self.disconnect()
        else:
            self.disconnect()
        return 0

    def send_bytes(self, data_bytes: bytes):
        self.print_thread(f">>>>>>> {data_bytes.decode('utf-8', errors='ignore')}")
        try:
            encrypted = self._encrypt_aes(data_bytes)
            self.send_bytes_raw(encrypted)
        except Exception:
            self.disconnect()

    def send_bytes_raw(self, data_bytes: bytes):
        with self.synchronizer:
            try:
                length_text = f"len:{len(data_bytes)}:".encode('utf-8')
                self.socket.sendall(length_text)
                self.socket.sendall(b'\x00')
                self.socket.sendall(data_bytes)
            except Exception:
                self.disconnect()

    def parse_message(self, message_data: bytes):
        try:
            message = self._decrypt_aes(message_data).decode('utf-8')
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
