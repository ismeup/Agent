import os
import sys
import ssl
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

from agent.config import KEY_FILE
from agent.client.connection_data import ConnectionData
from agent.client.client_manager import ClientManager

class RunController:
    def run(self, args: list):
        connection_data = ConnectionData()
            
        print(f"Connecting to {connection_data.get_host()}:{connection_data.get_port()}")

        identity = self.load_identity()
        cipher = self.get_cipher()
        
        if cipher and identity:
            ClientManager(connection_data, identity, cipher)
        else:
            print("Can not init RSA cipher")

    def get_cipher(self) -> PKCS1_v1_5.PKCS115_Cipher:
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            key_path = os.path.join(base_dir, "public.key")
            
            if not os.path.exists(key_path):
                key_path = "public.key"
                
            with open(key_path, "rb") as f:
                key_data = f.read()
                
            public_key = RSA.import_key(key_data)
            cipher = PKCS1_v1_5.new(public_key)
            return cipher
        except Exception as e:
            print(f"Error loading public.key: {e}")
            return None

    def load_identity(self) -> str:
        file_name = KEY_FILE
        if os.path.exists(file_name):
            try:
                with open(file_name, "r", encoding="utf-8") as f:
                    identity = f.read().replace("\r", "").replace("\n", "").strip()
                print(identity)
                return identity
            except Exception:
                print("Can't read identity.key!")
                sys.exit(1)
        else:
            print(f"File {KEY_FILE} is not found! Register new Agent in your application and provide identity.key file or register Agent in standalone mode by passing --register argument")
            sys.exit(1)
