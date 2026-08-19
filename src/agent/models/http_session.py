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


DEFAULT_MAX_CONTENT_SIZE = 1024 * 1024


def create_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", _LegacySSLAdapter())
    return session


def fetch_url(
    url: str,
    timeout: float = 5.0,
    headers: dict = None,
    max_content_size: int = DEFAULT_MAX_CONTENT_SIZE,
    discard_body: bool = False,
    method: str = "GET",
    data: bytes = None,
    raw: bool = False,
) -> tuple:

    with create_session() as session:
        if method.upper() == "POST" and data is not None:
            response = session.post(url, headers=headers, timeout=timeout, data=data, stream=True, verify=False)
        else:
            response = session.get(url, headers=headers, timeout=timeout, stream=True, verify=False)
        status_code = response.status_code

        if discard_body:
            response.close()
            return status_code, ""

        content: list[bytes] = []
        total = 0

        for chunk in response.iter_content(8192):
            if not chunk:
                continue
            remaining = max_content_size - total
            if len(chunk) > remaining:
                content.append(chunk[:remaining])
                break
            content.append(chunk)
            total += len(chunk)

        response.close()

        if raw:
            return status_code, b"".join(content)

        charset = response.encoding
        if not charset:
            charset = "utf-8"

        return status_code, b"".join(content).decode(charset, errors="replace")
