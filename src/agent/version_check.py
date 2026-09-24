import threading

from agent.apiclient.controllers import ApiConnector, OneTimeTokenStorage
from agent.config import AGENT_VERSION
from agent.client.connection_data import ConnectionData


def get_current_agent_version(connection_data: ConnectionData) -> int | None:
    api_connector = ApiConnector(connection_data, OneTimeTokenStorage())
    api_result = api_connector.post_operation("agent_version", "get_version")
    if not api_result.is_ok():
        return None
    version = api_result.get_answer().get("version")
    try:
        return int(version)
    except (TypeError, ValueError):
        return None


def check_agent_version(connection_data: ConnectionData):
    try:
        current_version = get_current_agent_version(connection_data)
        if current_version is not None and AGENT_VERSION < current_version:
            print(f"WARNING: Agent version {AGENT_VERSION} is outdated. Current version: {current_version}. Please update the agent.")
    except Exception:
        pass


def start_version_check(connection_data: ConnectionData) -> None:
    try:
        threading.Thread(target=check_agent_version, args=(connection_data,), daemon=True).start()
    except Exception:
        pass
