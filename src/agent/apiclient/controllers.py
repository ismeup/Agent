import threading
import requests
from agent.apiclient.models import TokenStorage, ApiResult, LoginData, LoginAnswer
from agent.client.connection_data import ConnectionData
from agent.exceptions import RemoteConnectException


class OneTimeTokenStorage(TokenStorage):
    def __init__(self):
        self._token = None
        self._lock = threading.Lock()

    def set_token(self, token: str):
        with self._lock:
            self._token = token

    def get_token(self) -> str:
        with self._lock:
            return self._token


class CmdLineInput:
    def _get_user_input(self) -> str:
        try:
            return input().strip()
        except (KeyboardInterrupt, EOFError):
            return ""

    def request_string(self, message: str, default_string: str = None) -> str:
        default_value_info = ""
        if default_string:
            default_value_info = f" [{default_string}]"

        print(f"{message}{default_value_info}: ", end="", flush=True)
        user_input = self._get_user_input()

        if not user_input:
            if default_string is not None:
                return default_string
            else:
                return self.request_string(message)
        return user_input

    def authenticate(self, appname: str, lifetime: int) -> LoginData:
        print(f"To register this {appname} in standalone mode, provide your login and password")
        print(
            'If you are using "Sign in with Apple" or "Sign in with Google" function, you can still set a password for your account')
        print('To do this, open "My account" page in your mobile app or in a web browser and set a new password')
        print(
            'This will not affect your "Sign in with Apple" or "Sign in with Google" functionality. You will be able to use these functions.')

        login = self.request_string("Enter your login")
        password = self.request_string(f"Enter password for {login}")
        return LoginData(login, password, appname, lifetime)


class ApiConnector:
    def __init__(self, connection_data: ConnectionData, token_storage: TokenStorage, debug_network: bool = False):
        self.connection_data = connection_data
        self.token_storage = token_storage
        self.debug_network = debug_network
        self.session = requests.Session()

    def _get_url(self, remote_component: str, operation: str) -> str:
        return f"{self.connection_data.get_url()}/api/service/{remote_component}/operation/{operation}"

    def _print_debug(self, line: str):
        if self.debug_network:
            print(line)

    def post_operation(self, remote_component: str, operation: str, parameters: dict = None) -> ApiResult:
        url = self._get_url(remote_component, operation)
        self._print_debug(url)

        payload = parameters if parameters is not None else {}
        token = self.token_storage.get_token()
        payload["token"] = token if token else ""

        self._print_debug(str(payload))

        try:
            response = self.session.post(url, json=payload, timeout=10)
            request_result_json = response.json()
            self._print_debug(str(request_result_json))

            is_ok = request_result_json.get("status", "error") == "ok"
            return ApiResult(is_ok, request_result_json, False)

        except Exception:
            print(f"Network error. Try again later or check connection URL: {self.connection_data.get_url()}")
            return ApiResult.interrupted()

    def authenticate(self, login_data: LoginData) -> bool:
        payload = {"loginData": login_data.to_json()}
        api_result = self.post_operation("login", "generate_token", payload)

        if not api_result.is_connection_interrupted():
            answer = api_result.get_answer().get("answer")
            if api_result.is_ok() and isinstance(answer, dict):
                login_answer = LoginAnswer.from_json(answer)
                if login_answer.code == 1:
                    self.token_storage.set_token(login_answer.token)
                    return True
        else:
            raise RemoteConnectException()
        return False