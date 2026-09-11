import os

AGENT_VERSION = 3
KEY_FILE = os.environ.get("AGENT_KEY_PATH") or "data/identity.key"
ISMEUP_HOST = os.environ.get("ISMEUP_HOST") or "ismeup.net"
ISMEUP_PORT = os.environ.get("ISMEUP_PORT") or "8787"
ISMEUP_URL = os.environ.get("ISMEUP_URL") or "https://ismeup.net"
ENABLE_PORT_PROXY = os.environ.get("ENABLE_PORT_PROXY", "").strip().lower() in ("1", "true", "yes", "on")
ENABLE_WOL = os.environ.get("ENABLE_WOL", "1").strip().lower() not in ("0", "false", "no", "off")
