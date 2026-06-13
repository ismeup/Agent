from agent.config import ISMEUP_HOST, ISMEUP_PORT, ISMEUP_URL;


class ConnectionData:
    def get_host(self) -> str:
        return ISMEUP_HOST;

    def get_port(self) -> int:
        return int(ISMEUP_PORT);

    def get_url(self) -> str:
        return ISMEUP_URL;
