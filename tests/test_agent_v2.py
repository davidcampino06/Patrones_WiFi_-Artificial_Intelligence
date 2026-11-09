"""Agente 2.0.0: la máscara real de la red, el origen de cada nombre, las capacidades en el reporte y las capturas que
pide el servidor (solo por su número)."""
import io
import json
import urllib.error

import pytest

from agent import capture_backends as backends
from agent import wifisense_agent as agent

SERVER = "https://wifisense.example.com"
SENSOR = "wsa_" + "s" * 43


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class NoContent(Response):
    status = 204


IPCONFIG_ES = """
Configuración IP de Windows

Adaptador de LAN inalámbrica Wi-Fi:

   Sufijo DNS específico para la conexión. . : uni.edu.co
   Vínculo: dirección IPv6 local. . . : fe80::1c2d:3e4f:5a6b:7c8d%12
   Dirección IPv4. . . . . . . . . . . . . . : 10.20.5.40
   Máscara de subred . . . . . . . . . . . . : 255.255.248.0
   Puerta de enlace predeterminada . . . . . : 10.20.0.1
"""

IPCONFIG_EN = """
Ethernet adapter Ethernet:

   IPv4 Address. . . . . . . . . . . : 192.168.56.1(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0

Wireless LAN adapter Wi-Fi:

   IPv4 Address. . . . . . . . . . . : 192.168.1.23(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
"""


def test_the_real_mask_of_the_network_is_read_from_ipconfig_in_spanish_and_english():
    assert agent.parse_ipconfig_prefix(IPCONFIG_ES, "10.20.5.40") == 21
    assert agent.parse_ipconfig_prefix(IPCONFIG_EN, "192.168.1.23") == 23
    assert agent.parse_ipconfig_prefix(IPCONFIG_EN, "192.168.1.2") is None  # 192.168.1.23 no es 192.168.1.2


def test_the_real_prefix_is_read_from_ip_addr_on_linux():
    text = "2: wlp2s0    inet 10.20.5.40/21 brd 10.20.7.255 scope global dynamic wlp2s0\n"

    assert agent.parse_ip_addr_prefix(text, "10.20.5.40") == 21
    assert agent.parse_ip_addr_prefix(text, "10.20.5.4") is None


def test_without_an_answer_from_the_system_the_network_is_assumed_to_be_a_24(monkeypatch):
    monkeypatch.setattr(agent, "run_command", lambda args, timeout=15: "")

    assert agent.network_prefix("192.168.1.2") == 24
    assert agent.network_prefix(None) == 24


def test_a_classmate_in_another_part_of_a_big_university_network_is_now_seen():
    table = {"10.20.7.12": "aa:bb:cc:00:00:01", "10.20.5.99": "aa:bb:cc:00:00:02", "10.30.0.5": "aa:bb:cc:00:00:03"}

    assert set(agent.same_subnet(table, "10.20.5.40", 24)) == {"10.20.5.99"}  # lo que hacía la 1.9
    assert set(agent.same_subnet(table, "10.20.5.40", 21)) == {"10.20.7.12", "10.20.5.99"}


def test_a_huge_network_is_woken_only_around_this_computer(monkeypatch):
    sent = []

    class Socket:
        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def sendto(self, data, address):
            sent.append(address[0])

    monkeypatch.setattr(agent.socket, "socket", Socket)
    agent.wake_neighbors("10.20.5.40", 16)

    assert len(sent) == 1022  # /22, no las 65 534 direcciones de una /16
    assert "10.20.4.1" in sent and "10.20.7.254" in sent and "10.20.8.1" not in sent


@pytest.mark.parametrize("announced, dhcp, router, hostname, name, source", [
    ({"name": "iPhone de Ana"}, {}, None, None, "iPhone de Ana", "ANNOUNCED"),
    ({}, {"name": "Galaxy-A54"}, "galaxy-a54.lan", None, "Galaxy-A54", "CONFIRMED"),
    ({}, {}, "Portatil-de-Juan.lan", "PC-RARO", "Portatil-de-Juan", "ROUTER"),
    ({}, {}, None, "PC-SALA", "PC-SALA", "DNS"),
    ({}, {}, None, None, None, None),
])
def test_every_name_says_where_it_came_from(announced, dhcp, router, hostname, name, source):
    device = agent.describe_device("192.168.1.23", "da:a1:19:00:00:01", "sal", "192.168.1.2", "192.168.1.1",
                                   hostname, announced, dhcp, router)

    assert device.get("name") == name
    assert device.get("nameSource") == source


def test_a_vendor_estimated_from_the_mac_is_never_presented_as_the_name():
    device = agent.describe_device("192.168.1.23", "fc:fb:fb:11:22:33", "sal", "192.168.1.2", "192.168.1.1", None, {})

    assert device["vendor"] == "Apple" and "name" not in device and "nameSource" not in device


def test_router_names_are_asked_to_the_router_and_a_silent_router_gives_none():
    class Source:
        def names(self, ips):
            return {"192.168.1.23": "Portatil-de-Ana.lan", "192.168.1.24": "192.168.1.24"}

    assert agent.router_names("192.168.1.1", ["192.168.1.23", "192.168.1.24"], lambda gw: Source()) == {
        "192.168.1.23": "Portatil-de-Ana.lan"}  # una "IP como nombre" no es un nombre

    class Broken:
        def names(self, ips):
            raise OSError("el router no tiene DNS")

    assert agent.router_names("192.168.1.1", ["192.168.1.23"], lambda gw: Broken()) == {}
    assert agent.router_names(None, ["192.168.1.23"]) == {}


@pytest.mark.parametrize("answer, expected", [
    ({"captureId": 40, "maxSeconds": 30, "maxPackets": 5000, "maxBytes": 20971520},
     {"captureId": 40, "maxSeconds": 30, "maxPackets": 5000, "maxBytes": 20971520}),
    ({"captureId": 40, "command": "pktmon start --pkt-size 0", "maxSeconds": "60"}, {"captureId": 40}),
    ({"captureId": "40"}, None), ({"captureId": False}, None), ({"captureId": -1}, None), ([], None), (None, None),
])
def test_the_server_can_only_ask_for_a_capture_by_its_number_and_limits(answer, expected):
    assert agent.capture_task_of(answer) == expected


def test_the_capture_is_run_with_the_sensor_key_and_only_counts_are_posted(monkeypatch, tmp_path):
    calls = []

    def opener(request, timeout):
        calls.append((request.get_method(), request.full_url, request.get_header("X-agent-key"),
                      json.loads(request.data) if request.data else None))
        if request.full_url.endswith("/state"):
            return Response(b'{"captureId": 40, "stop": false}')
        return Response(b'{"id": 40, "status": "COMPLETED"}')

    class Tool:
        code = "PACKET_SOCKET"

        def check(self, own_ip=None):
            return backends.Check(True, True, interfaces=1)

        def capture(self, session):
            from tests import capture_samples as samples
            from agent import packet_parser
            session.stats.add(packet_parser.parse(samples.https_out(), 1), 10.0)
            return backends.Run("wlan0")

    monkeypatch.setattr(agent, "local_ip", lambda: "192.168.1.2")
    monkeypatch.setattr(agent, "network_prefix", lambda ip: 24)
    monkeypatch.setattr(agent.traffic_capture, "log_path", lambda: tmp_path / "capturas.log")
    monkeypatch.setattr(agent.traffic_capture.capture_files, "captures_dir",
                        lambda base=None: (tmp_path / "capturas").mkdir(exist_ok=True) or tmp_path / "capturas")

    result = agent.run_capture_task({"captureId": 40, "maxSeconds": 5}, SERVER, SENSOR, {"captureConsent": True},
                                    opener=opener, backends=[Tool()])

    posted = [c for c in calls if c[0] == "POST"]
    assert posted[0][1] == SERVER + "/api/agent/captures" and posted[0][2] == SENSOR
    assert posted[0][3]["captureId"] == 40 and posted[0][3]["packetCount"] == 1
    assert result["status"] == "COMPLETED" and "192.168" not in json.dumps(posted[0][3])


def test_while_waiting_the_sensor_asks_for_captures_and_a_home_agent_stops_asking_after_404(monkeypatch):
    clock, asked, ran = [0.0], [], []

    def sleep(seconds):
        clock[0] += seconds

    def opener(request, timeout):
        asked.append(request.full_url.rsplit("/api/agent/", 1)[1])
        if request.full_url.endswith("/scans/next"):
            raise urllib.error.HTTPError(request.full_url, 404, "no", {}, None)
        if len([a for a in asked if a == "captures/next"]) == 2:
            return Response(b'{"captureId": 41, "maxSeconds": 20, "maxPackets": 100, "maxBytes": 1048576}')
        return NoContent(b"")

    monkeypatch.setattr(agent, "run_capture_task", lambda task, server, key, config, opener: ran.append(task))
    agent.wait_watching_tasks(120, SERVER, SENSOR, "sal", {"captureConsent": True}, sleep=sleep,
                              clock=lambda: clock[0], opener=opener)

    assert asked.count("scans/next") == 1  # 404: un sensor no tiene escaneos; no se vuelve a preguntar
    assert asked.count("captures/next") == 3
    assert ran == [{"captureId": 41, "maxSeconds": 20, "maxPackets": 100, "maxBytes": 1048576}]


def test_a_home_agent_never_asks_for_captures(monkeypatch):
    asked = []

    def opener(request, timeout):
        asked.append(request.full_url)
        return NoContent(b"")

    clock = [0.0]
    agent.wait_watching_scans(60, SERVER, SENSOR, "sal", sleep=lambda s: clock.__setitem__(0, clock[0] + s),
                              clock=lambda: clock[0], opener=opener)

    assert asked and all(url.endswith("/scans/next") for url in asked)


def test_the_capabilities_are_checked_at_most_every_ten_minutes_or_when_the_consent_changes(monkeypatch):
    checks = []
    monkeypatch.setattr(agent, "local_ip", lambda: "192.168.1.2")
    monkeypatch.setattr(agent, "_capabilities_cache", {"at": -10_000, "value": None, "consent": None})

    monkeypatch.setattr(agent, "monitor_mode_hint", lambda: None)

    def fake(config, own_ip, backends=None, monitor_hint=None):
        checks.append(config.get("captureConsent"))
        return {"captureConsent": bool(config.get("captureConsent"))}
    monkeypatch.setattr(agent.traffic_capture, "capabilities", fake)

    agent.agent_capabilities({}, now=0)
    agent.agent_capabilities({}, now=300)
    agent.agent_capabilities({"captureConsent": True}, now=301)
    agent.agent_capabilities({"captureConsent": True}, now=1000)

    assert checks == [None, True, True]


def test_capture_consent_is_saved_only_in_this_computers_configuration(monkeypatch, tmp_path, capsys):
    path = tmp_path / "agent.json"
    path.write_text(json.dumps({"server": SERVER, "salt": "sal"}))
    monkeypatch.setattr(agent, "config_path", lambda: path)

    assert agent.main(["capture-consent", "on"]) == 0
    assert json.loads(path.read_text())["captureConsent"] is True and "PERMITIDAS" in capsys.readouterr().out
    assert agent.main(["capture-consent", "off"]) == 0
    assert json.loads(path.read_text())["captureConsent"] is False
    assert json.loads(path.read_text())["salt"] == "sal"


def test_the_report_carries_the_capabilities_and_a_capture_asked_in_the_answer_is_run(monkeypatch, tmp_path):
    monkeypatch.setenv("WIFISENSE_AGENT_KEY", SENSOR)
    monkeypatch.setattr(agent, "traffic_state_path", lambda: tmp_path / "traffic.json")
    monkeypatch.setattr(agent, "config_path", lambda: tmp_path / "agent.json")
    monkeypatch.setattr(agent, "ensure_salt", lambda config: "sal")
    monkeypatch.setattr(agent, "collect", lambda salt: {"deviceCount": 0, "openPorts": []})
    monkeypatch.setattr(agent, "traffic_counters", lambda: {})
    monkeypatch.setattr(agent, "agent_capabilities", lambda config: {"captureConsent": False, "npcap": True})
    sent, ran = [], []
    monkeypatch.setattr(agent, "send", lambda report, server, key: sent.append(report) or {"captureId": 42})
    monkeypatch.setattr(agent, "next_capture", lambda server, key: {"captureId": 42, "maxSeconds": 10})
    monkeypatch.setattr(agent, "run_capture_task", lambda task, server, key, config: ran.append(task))

    assert agent.command_run(agent.argparse.Namespace(once=True, interval=300)) == 0
    assert sent[0]["capabilities"] == {"captureConsent": False, "npcap": True}
    assert ran == [{"captureId": 42, "maxSeconds": 10}]


def test_a_capture_announced_in_the_answer_but_already_taken_is_not_run_with_made_up_limits(monkeypatch, tmp_path):
    monkeypatch.setenv("WIFISENSE_AGENT_KEY", SENSOR)
    monkeypatch.setattr(agent, "traffic_state_path", lambda: tmp_path / "traffic.json")
    monkeypatch.setattr(agent, "config_path", lambda: tmp_path / "agent.json")
    monkeypatch.setattr(agent, "ensure_salt", lambda config: "sal")
    monkeypatch.setattr(agent, "collect", lambda salt: {"deviceCount": 0, "openPorts": []})
    monkeypatch.setattr(agent, "traffic_counters", lambda: {})
    monkeypatch.setattr(agent, "agent_capabilities", lambda config: None)
    monkeypatch.setattr(agent, "send", lambda report, server, key: {"captureId": 43})
    monkeypatch.setattr(agent, "next_capture", lambda server, key: None)
    ran = []
    monkeypatch.setattr(agent, "run_capture_task", lambda *args: ran.append(args))

    assert agent.command_run(agent.argparse.Namespace(once=True, interval=300)) == 0
    assert ran == []


def test_the_version_is_2_0_0():
    assert agent.AGENT_VERSION == "2.0.0"


@pytest.mark.parametrize("text, expected", [
    ("    Network monitor mode                  : Supported\n", True),
    ("    Modo de monitor de red                : Compatible\n", True),
    ("    Network monitor mode                  : Not supported\n", False),
    ("    Modo de monitor de red                : No compatible\n", False),
    ("    FIPS 140-2 mode                       : Supported\n", None),
    ("", None),
])
def test_the_monitor_mode_the_card_declares_is_read_but_never_turned_on(text, expected):
    assert agent.parse_monitor_mode(text) == expected
