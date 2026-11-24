from types import SimpleNamespace

import pytest
import typer

from guardian.cli import ui as ui_cli
from guardian.core.config import GuardianSettings


class FakeServer:
    def __init__(self):
        self.closed = False

    def serve_forever(self):
        raise KeyboardInterrupt

    def server_close(self):
        self.closed = True


@pytest.fixture
def settings(tmp_path, monkeypatch):
    value = GuardianSettings(_env_file=None, data_dir=tmp_path, cli_approvers=["alice"])
    monkeypatch.setattr(ui_cli, "load_settings", lambda: value)
    return value


def test_ui_prints_url_and_stops(settings, monkeypatch, capsys):
    server = FakeServer()
    seen = {}

    def fake_make_server(app, port):
        seen["port"] = port
        app.port = 4321
        return server

    opened = []
    monkeypatch.setattr(ui_cli, "make_server", fake_make_server)
    monkeypatch.setattr(ui_cli.webbrowser, "open", opened.append)
    monkeypatch.setattr(ui_cli, "current_user", lambda: "bob")
    ui_cli.ui(port=0, no_open=False)
    out = capsys.readouterr().out
    assert "http://127.0.0.1:4321/?token=" in out
    assert "GUARDIAN_CLI_APPROVERS" in out  # bob is not an approver
    assert opened
    assert opened[0].startswith("http://127.0.0.1:4321/?token=")
    assert server.closed
    assert seen["port"] == 0


def test_ui_no_open(settings, monkeypatch, capsys):
    monkeypatch.setattr(ui_cli, "make_server", lambda app, port: FakeServer())
    opened = []
    monkeypatch.setattr(ui_cli.webbrowser, "open", opened.append)
    monkeypatch.setattr(ui_cli, "current_user", lambda: "alice")
    ui_cli.ui(port=8765, no_open=True)
    assert opened == []
    assert "GUARDIAN_CLI_APPROVERS" not in capsys.readouterr().out


def test_ui_port_in_use(settings, monkeypatch):
    def fail(app, port):
        raise OSError(48, "Address already in use")

    monkeypatch.setattr(ui_cli, "make_server", fail)
    with pytest.raises(typer.Exit):
        ui_cli.ui(port=8765, no_open=True)


def test_hook_resumes_the_remediation_graph(settings, monkeypatch):
    from guardian.remediation import runtime

    calls = []
    monkeypatch.setattr(
        runtime, "submit_decision", lambda *args, **kwargs: calls.append((args, kwargs))
    )
    handler = ui_cli.decision_handler(settings)
    case, decision = SimpleNamespace(id="rc_1"), object()
    handler(case, decision)
    assert calls == [((settings, "rc_1", decision), {"already_recorded": True})]
