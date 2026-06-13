import urllib.parse
import ssl
import socket
from datetime import datetime, timezone
from cryptography import x509
from agent.interfaces.checker import Checker

class CertificateCheck(Checker):
    def __init__(self):
        self.url = ""
        self.days = 443
        self.status = False
        self.rest_days = -1

    def run_check(self, params: dict):
        self.url = params.get("url", "")
        self.days = int(params.get("days", 443))

        try:
            parsed_url = urllib.parse.urlparse(self.url)
            hostname = parsed_url.hostname or self.url
            port = parsed_url.port or 443

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers("ALL:@SECLEVEL=0")
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1
            except (AttributeError, ssl.SSLError):
                pass

            with socket.create_connection((hostname, port), timeout=5.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)

            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
            cert = x509.load_pem_x509_certificate(pem_cert.encode())
            expiry_date = cert.not_valid_after_utc

            now = datetime.now(timezone.utc)
            delta = expiry_date - now
            self.rest_days = delta.days
            self.status = self.rest_days >= self.days
        except Exception:
            self.status = False

    def get_operation_result(self) -> dict:
        return {"status": self.status, "daysRest": self.rest_days}
