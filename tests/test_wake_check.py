import agent.models.wake_check as wake_module
from agent.models.wake_check import WakeOnLanCheck


class FakeSocket:
    def __init__(self, sent):
        self.sent = sent

    def setsockopt(self, *args):
        pass

    def sendto(self, packet, addr):
        self.sent.append((packet, addr))

    def close(self):
        pass


def test_wake_rejected_when_wol_disabled(monkeypatch):
    monkeypatch.setattr(wake_module, "ENABLE_WOL", False)
    sent = []
    monkeypatch.setattr(wake_module.socket, "socket", lambda *a, **k: FakeSocket(sent))

    checker = WakeOnLanCheck()
    checker.run_check({"mac": "AA:BB:CC:DD:EE:FF", "host": "10.0.0.5"})
    result = checker.get_operation_result()

    assert result["status"] is False
    assert "disabled" in result.get("error", "")
    assert sent == []


def test_wake_sends_magic_packet_when_enabled(monkeypatch):
    monkeypatch.setattr(wake_module, "ENABLE_WOL", True)
    monkeypatch.setattr(WakeOnLanCheck, "_get_broadcast_address", lambda self, host: "192.168.1.255")
    sent = []
    monkeypatch.setattr(wake_module.socket, "socket", lambda *a, **k: FakeSocket(sent))

    checker = WakeOnLanCheck()
    checker.run_check({"mac": "AA:BB:CC:DD:EE:FF", "host": "10.0.0.5"})
    result = checker.get_operation_result()

    assert result["status"] is True
    assert "error" not in result
    packet = b"\xff" * 6 + bytes.fromhex("aabbccddeeff") * 16
    assert sent == [(packet, ("192.168.1.255", 9)), (packet, ("192.168.1.255", 7))]
