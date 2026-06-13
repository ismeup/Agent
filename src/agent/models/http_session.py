import ssl
import requests
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class _LegacySSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (AttributeError, ssl.SSLError):
            pass
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)


def create_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", _LegacySSLAdapter())
    return session
