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
