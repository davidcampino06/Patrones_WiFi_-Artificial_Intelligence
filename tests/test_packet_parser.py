"""Cabeceras -> protocolo, puertos y difusión, sin abrir nunca el contenido del paquete."""
import dataclasses
import struct

import pytest

from agent import packet_parser as parser
from tests import capture_samples as samples


@pytest.mark.parametrize("frame, protocol, service", [
    (samples.https_out(), "HTTPS", 443),
    (samples.https_in(), "HTTPS", 443),
    (samples.dns_query(), "DNS", 53),
    (samples.mdns(), "MDNS", 5353),
    (samples.dhcp_discover(), "DHCP", 67),
])
def test_the_application_protocol_comes_only_from_the_port(frame, protocol, service):
    info = parser.parse(frame, parser.LINK_ETHERNET)

    assert info.protocol == protocol
    assert info.service_port == service
    assert not info.malformed


def test_nothing_of_the_content_reaches_the_packet_info():
    info = parser.parse(samples.https_out(), parser.LINK_ETHERNET)

    text = repr(dataclasses.asdict(info))
    assert "password" not in text and "cookie" not in text and "secreto" not in text


def test_arp_is_broadcast_and_mdns_is_multicast_but_never_both():
    arp = parser.parse(samples.arp_request(), parser.LINK_ETHERNET)
    mdns = parser.parse(samples.mdns(), parser.LINK_ETHERNET)
    dhcp = parser.parse(samples.dhcp_discover(), parser.LINK_ETHERNET)

    assert arp.protocol == "ARP" and arp.broadcast and not arp.multicast
    assert mdns.multicast and not mdns.broadcast
    assert dhcp.broadcast
