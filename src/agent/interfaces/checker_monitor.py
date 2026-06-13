import base64
import json
import uuid
import requests
from abc import abstractmethod
from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad
from agent.interfaces.checker import Checker

class CheckerMonitor(Checker):
    def __init__(self):
        self.url = ""
        self.key = ""
        self.key_bytes = None
        self.ciphers_inited = False

    def parse_monitor_parameters(self, parameter: dict):
        self.url = f"http://{parameter.get('host')}:{parameter.get('port')}"
        self.key = parameter.get('key', '')
        self._init_ciphers()

    def _init_ciphers(self):
        try:
            sha = SHA1.new(self.key.encode('utf-8'))
            self.key_bytes = sha.digest()[:16]
            self.ciphers_inited = True
        except Exception:
            self.ciphers_inited = False

    def _encrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key_bytes, AES.MODE_ECB)
        return cipher.encrypt(pad(data, AES.block_size, style='pkcs7'))

    def _decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self.key_bytes, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), AES.block_size, style='pkcs7')

    def run_check(self, check_operation_parameter: dict):
        self.parse_monitor_parameters(check_operation_parameter)
        if self.ciphers_inited:
            self.parse_check_parameters(check_operation_parameter)
            string_result = "_not_received"
            salt = str(uuid.uuid4())
            try:
                data = self.get_request_json()
                data["operation"] = self.get_operation_name()
                data["salt"] = salt
                
                encrypted = self._encrypt(json.dumps(data).encode('utf-8'))
                data_to_send = base64.b64encode(encrypted)
                
                response = requests.post(self.url, data=data_to_send, timeout=5)
                
                encrypted_received = base64.b64decode(response.content)
                decrypted_received = self._decrypt(encrypted_received)
                
                string_result = decrypted_received.decode('utf-8')
                json_object = json.loads(string_result)
                
                self.parse_result(json_object.get("answer", ""))
            except Exception as e:
                print(f"Message was: {string_result}")
                print(f"Salt was: {salt}")
                print(str(e))
        else:
            print("Can't init ciphers")

    def get_request_json(self) -> dict:
        return {}

    @abstractmethod
    def get_operation_name(self) -> str:
        pass

    @abstractmethod
    def parse_result(self, result: str):
        pass

    @abstractmethod
    def parse_check_parameters(self, check_operation_parameter: dict):
        pass
