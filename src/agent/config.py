import os

AGENT_VERSION = 3
KEY_FILE = os.environ.get("AGENT_KEY_PATH") or "data/identity.key"
ISMEUP_HOST = os.environ.get("ISMEUP_HOST") or "ismeup.net"
ISMEUP_PORT = os.environ.get("ISMEUP_PORT") or "8787"
ISMEUP_URL = os.environ.get("ISMEUP_URL") or "https://ismeup.net"