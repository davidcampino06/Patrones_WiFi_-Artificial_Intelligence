"""Una captura completa desde el pedido hasta la entrega: permiso local, herramienta, parada, conteos y limpieza."""
import json

import pytest

from agent import capture_backends as backends
from agent import traffic_capture
from tests import capture_samples as samples


class OneShot:
    """Una herramienta de prueba que 'captura' unos paquetes, o falla como se le diga."""
    code = "NPCAP"

    def __init__(self, frames=(), fail=None, usable=True, until_stopped=False):
        self.frames, self.fail, self.usable, self.until_stopped = list(frames), fail, usable, until_stopped
        self.temp_seen = None

    def check(self, own_ip=None):
        return backends.Check(self.usable, True, None if self.usable else "PERMISSION_DENIED", interfaces=1,
                              monitor_mode=False)

    def capture(self, session):
        from agent import packet_parser
        self.temp_seen = session.temp.path
        session.temp.file("captura.pcapng").write_bytes(b"cabeceras")
        if self.fail:
            raise self.fail
        for i, frame in enumerate(self.frames):
            session.stats.add(packet_parser.parse(frame, 1), 100.0 + i / 10)
        if self.until_stopped:
            started = session.clock()
            for _ in range(500):
                if session.over(started):
                    break
                session.sleep(0.01)
        return backends.Run("Intel Wi-Fi", dropped_by_tool=0)


@pytest.fixture
def delivered(monkeypatch, tmp_path):
    sent = []
    monkeypatch.setattr(traffic_capture, "log_path", lambda: tmp_path / "capturas.log")
    return sent


def capture(task, config, backend, delivered, tmp_path, ask_stop=lambda: False, watcher_every=60):
    lines = []
    result = traffic_capture.run_capture(task, config, "2.0.0", delivered.append, ask_stop, "192.168.1.2",
                                         ["192.168.1.2/24"], backends=[backend], temp_root=tmp_path,
                                         log=lines.append, watcher_every=watcher_every)
    return result, lines


ALLOWED = {"captureConsent": True}


def test_without_local_consent_nothing_is_captured_and_the_reason_is_delivered(delivered, tmp_path):
    backend = OneShot([samples.https_out()])
    result, lines = capture({"captureId": 5, "maxSeconds": 10}, {}, backend, delivered, tmp_path)

    assert result == {"captureId": 5, "status": "FAILED", "failureReason": "NO_CONSENT", "agentVersion": "2.0.0"}
    assert delivered == [result] and backend.temp_seen is None
    assert "capture-consent on" in lines[0]


def test_a_capture_delivers_only_counts_and_deletes_its_temporary_files(delivered, tmp_path):
    backend = OneShot([samples.https_out(), samples.https_in(), samples.dns_query(), samples.arp_request()])
    result, lines = capture({"captureId": 6, "maxSeconds": 10, "maxPackets": 500}, ALLOWED, backend, delivered,
                            tmp_path)

    assert result["status"] == "COMPLETED" and result["packetCount"] == 4 and result["captureTool"] == "NPCAP"
    assert result["interfaceName"] == "Intel Wi-Fi" and result["droppedByTool"] == 0
    text = json.dumps(delivered[0])
    assert "192.168" not in text and "142.250" not in text and "secreto" not in text
    assert not backend.temp_seen.exists()
    assert any("Solo cabeceras" in line for line in lines)
    logged = json.loads((tmp_path / "capturas.log").read_text().splitlines()[-1])
    assert logged["captureId"] == 6 and logged["status"] == "COMPLETED" and "interfaceName" not in logged


def test_a_tool_that_fails_gives_its_reason_and_no_partial_data(delivered, tmp_path):
    backend = OneShot(fail=backends.CaptureFailed("PERMISSION_DENIED", "Access is denied."))
    result, _ = capture({"captureId": 7}, ALLOWED, backend, delivered, tmp_path)

    assert result == {"captureId": 7, "status": "FAILED", "failureReason": "PERMISSION_DENIED",
                      "agentVersion": "2.0.0", "captureTool": "NPCAP"}
    assert not backend.temp_seen.exists()


def test_an_unexpected_error_is_a_capture_error_not_a_crash(delivered, tmp_path):
    result, _ = capture({"captureId": 8}, ALLOWED, OneShot(fail=ZeroDivisionError("bug")), delivered, tmp_path)

    assert result["failureReason"] == "CAPTURE_ERROR"


def test_with_no_usable_tool_the_reason_is_the_missing_permission(delivered, tmp_path):
    result, _ = capture({"captureId": 9}, ALLOWED, OneShot(usable=False), delivered, tmp_path)

    assert result["failureReason"] == "PERMISSION_DENIED"


def test_an_administrator_asking_to_stop_ends_the_capture_as_cancelled(delivered, tmp_path):
    result, _ = capture({"captureId": 10, "maxSeconds": 60}, ALLOWED, OneShot([samples.mdns()], until_stopped=True),
                        delivered, tmp_path, ask_stop=lambda: True, watcher_every=0.01)

    assert result["status"] == "COMPLETED" and result["stopReason"] == "CANCELLED" and result["packetCount"] == 1


@pytest.mark.parametrize("task", [{}, {"captureId": "1; rm -rf /"}, {"captureId": True}, {"captureId": -3}])
def test_a_task_without_a_valid_number_is_ignored(task, delivered, tmp_path):
    assert capture(task, ALLOWED, OneShot(), delivered, tmp_path)[0] == {} and delivered == []


def test_a_delivery_that_fails_is_logged_and_does_not_crash(monkeypatch, tmp_path):
    monkeypatch.setattr(traffic_capture, "log_path", lambda: tmp_path / "capturas.log")
    lines = []

    def deliver(_result):
        raise ConnectionError("sin internet")

    traffic_capture.run_capture({"captureId": 11}, {}, "2.0.0", deliver, lambda: False, None, [],
                                backends=[OneShot()], temp_root=tmp_path, log=lines.append)
    assert any("No se entregó" in line for line in lines)


def test_capabilities_say_what_can_be_used_now_not_what_merely_exists():
    caps = traffic_capture.capabilities({"captureConsent": True}, "192.168.1.2",
                                        backends=[OneShot(usable=False), _Packet()], elevated=lambda: False)

    assert caps == {"elevated": False, "captureConsent": True, "npcap": False, "pktmon": False, "rawSocket": False,
                    "packetSocket": True, "monitorMode": "UNSUPPORTED", "captureInterfaces": 1}


class _Packet:
    code = "PACKET_SOCKET"

    def check(self, own_ip=None):
        return backends.Check(True, True, interfaces=1)


def test_consent_is_only_true_when_it_was_given_explicitly():
    assert not traffic_capture.consent_given({})
    assert not traffic_capture.consent_given({"captureConsent": "true"})
    assert traffic_capture.consent_given(traffic_capture.set_consent({}, True))
    assert not traffic_capture.consent_given(traffic_capture.set_consent({"captureConsent": True}, False))


def test_the_check_text_explains_why_a_tool_cannot_be_used():
    caps = {"elevated": False, "captureConsent": False, "npcap": False, "pktmon": False, "rawSocket": False,
            "packetSocket": False, "monitorMode": "UNKNOWN", "captureInterfaces": 0}
    text = traffic_capture.describe_capabilities(caps, {"PKTMON": backends.Check(
        False, True, "PERMISSION_DENIED", "pktmon necesita que el agente corra como administrador.")})

    assert "capture-consent on" in text and "ninguna" in text and "administrador" in text
