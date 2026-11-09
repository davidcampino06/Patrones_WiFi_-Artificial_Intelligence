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
