import agent.models.mac_check as mac_module
from agent.models.mac_check import MacCheck


def test_get_mac_rejected_when_wol_disabled(monkeypatch):
    monkeypatch.setattr(mac_module, "ENABLE_WOL", False)

    checker = MacCheck()
    checker.run_check({"host": "10.0.0.5"})
    result = checker.get_operation_result()

    assert result["status"] is False
    assert result["mac"] == ""
    assert "disabled" in result.get("error", "")


def test_get_mac_runs_when_wol_enabled(monkeypatch):
    monkeypatch.setattr(mac_module, "ENABLE_WOL", True)
    monkeypatch.setattr(mac_module.socket, "gethostbyname", lambda host: "10.0.0.5")
    monkeypatch.setattr(mac_module.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(MacCheck, "_get_mac", lambda self, ip: "aa:bb:cc:dd:ee:ff")

    checker = MacCheck()
    checker.run_check({"host": "10.0.0.5"})
    result = checker.get_operation_result()

    assert result["status"] is True
    assert result["mac"] == "aa:bb:cc:dd:ee:ff"
    assert "error" not in result
