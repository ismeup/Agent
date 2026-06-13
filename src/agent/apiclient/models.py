import json
from urllib.parse import urlparse


class TokenStorage:
    def get_token(self) -> str:
        raise NotImplementedError

    def set_token(self, token: str):
        raise NotImplementedError


class LoginData:
    def __init__(self, login: str, password: str, app_name: str, lifetime: int):
        self.login = login
        self.password = password
        self.app_name = app_name
        self.lifetime = lifetime

    def to_json(self) -> dict:
        return {
            "login": self.login,
            "password": self.password,
            "appname": self.app_name,
            "lifetime": self.lifetime
        }


class LoginAnswer:
    def __init__(self, message: str = "", code: int = 0, token: str = ""):
        self.message = message
        self.code = code
        self.token = token

    @staticmethod
    def from_json(json_obj: dict) -> 'LoginAnswer':
        return LoginAnswer(
            message=json_obj.get("message", ""),
            code=json_obj.get("code", 0),
            token=json_obj.get("token", "")
        )


class ApiResult:
    def __init__(self, is_ok: bool, answer: dict, connection_interrupted: bool):
        self._is_ok = is_ok
        self._answer = answer
        self._connection_interrupted = connection_interrupted

    def is_ok(self) -> bool:
        return self._is_ok

    def get_answer(self) -> dict:
        return self._answer

    def is_connection_interrupted(self) -> bool:
        return self._connection_interrupted

    @staticmethod
    def empty() -> 'ApiResult':
        return ApiResult(False, {}, False)

    @staticmethod
    def interrupted() -> 'ApiResult':
        return ApiResult(False, {}, True)

