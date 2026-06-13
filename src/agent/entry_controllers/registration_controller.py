import os

from agent.client.connection_data import ConnectionData
from agent.config import KEY_FILE
from agent.models.server_watcher import ServerWatcher
from agent.apiclient.controllers import CmdLineInput, OneTimeTokenStorage, ApiConnector


class RegistrationController:
    def run(self, args: list):
        identity_file = KEY_FILE
        if os.path.exists(identity_file):
            print(
                "identity.key file exists. Remove it first, if you want to register a new Agent. Otherwise run the Agent without --register argument")
            return

        cmd_input = CmdLineInput()
        token_storage = OneTimeTokenStorage()
        connector = ApiConnector(ConnectionData(), token_storage, debug_network=False)

        login_data = cmd_input.authenticate(appname="Agent", lifetime=3600)

        try:
            if connector.authenticate(login_data):
                print("Logged in")
                new_watcher_name = cmd_input.request_string("Enter name for new Agent")
                server_watcher = ServerWatcher.create_by_name(new_watcher_name)

                payload = {"serverWatcher": server_watcher.to_json()}
                api_result = connector.post_operation("server_watchers", "generate", payload)

                if not api_result.is_connection_interrupted() and api_result.is_ok():
                    answer = api_result.get_answer()
                    watcher_data = answer.get("watcher", {})

                    new_watcher = ServerWatcher.from_json(watcher_data)

                    if new_watcher.key:
                        print(f"Agent registered! Key is: {new_watcher.key}")
                        print("Creating identity.key file...", end="", flush=True)

                        if self.save_identity(new_watcher.key):
                            print("OK")
                            print("File identity.key created. Now you can run Agent as usual!")
                        else:
                            print("FAIL")
                            print("File identity.key was not created! Check directory permissions")
                    else:
                        print("Unknown error: Server returned empty key!")
                else:
                    print("Something went wrong during generation. Try again")
            else:
                print("Login or password mismatch")

        except Exception as e:
            print(f"Connection failed or interrupted: {e}")

    def save_identity(self, key: str) -> bool:
        try:
            with open(KEY_FILE, "w", encoding="utf-8") as f:
                f.write(key)
            return True
        except Exception:
            return False
