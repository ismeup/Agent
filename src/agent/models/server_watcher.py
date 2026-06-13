class ServerWatcher:
    def __init__(self, id_val=0, name="", key="", last_online=0, is_main=False, checks_count=0):
        self.id = id_val
        self.name = name
        self.key = key
        self.last_online = last_online
        self.is_main = is_main
        self.checks_count = checks_count

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "key": self.key,
            "lastOnline": self.last_online,
            "isMain": self.is_main,
            "checksCount": self.checks_count
        }

    @staticmethod
    def from_json(json_obj: dict) -> 'ServerWatcher':
        return ServerWatcher(
            id_val=json_obj.get("id", 0),
            name=json_obj.get("name", ""),
            key=json_obj.get("key", ""),
            last_online=json_obj.get("lastOnline", 0),
            is_main=json_obj.get("isMain", False),
            checks_count=json_obj.get("checksCount", 0)
        )

    @staticmethod
    def create_by_name(name: str) -> 'ServerWatcher':
        return ServerWatcher(name=name)
