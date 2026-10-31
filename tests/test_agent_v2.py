"""Agente: la máscara real de la red, el origen de cada nombre y los nombres que da el router."""
import io
import json

import pytest

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
