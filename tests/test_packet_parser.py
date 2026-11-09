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


def test_icmp_igmp_and_icmpv6_are_recognised():
    icmp = samples.ethernet(samples.ROUTER_MAC, samples.OWN_MAC, 0x0800,
                            samples.ipv4("192.168.1.2", "1.1.1.1", 1, b"\x08\x00"))
    igmp = samples.ethernet(samples.MDNS_MAC, samples.OWN_MAC, 0x0800,
                            samples.ipv4("192.168.1.2", "224.0.0.22", 2, b"\x22"))

    assert parser.parse(icmp, parser.LINK_ETHERNET).protocol == "ICMP"
    assert parser.parse(igmp, parser.LINK_ETHERNET).protocol == "IGMP"
    v6 = parser.parse(samples.icmpv6_multicast(), parser.LINK_ETHERNET)
    assert v6.protocol == "ICMPV6" and v6.multicast and v6.destination == "ff02::1"


def test_ipv6_extension_headers_are_skipped_to_find_the_ports():
    hop_by_hop = bytes([17, 0]) + b"\x00" * 6  # siguiente: UDP; largo 0 => 8 bytes
    frame = samples.ethernet(samples.ROUTER_MAC, samples.OWN_MAC, 0x86DD,
                             samples.ipv6("2800:e2::5", "2800:e2::1", 0, hop_by_hop + samples.udp(40000, 123)))

    info = parser.parse(frame, parser.LINK_ETHERNET)
    assert info.protocol == "NTP" and info.service_port == 123


def test_a_vlan_tag_is_skipped():
    tagged = samples.OWN_MAC + samples.ROUTER_MAC + struct.pack("!HH", 0x8100, 10) + samples.https_out()[12:]

    assert parser.parse(tagged, parser.LINK_ETHERNET).protocol == "HTTPS"


def test_a_later_fragment_has_no_ports_and_is_not_guessed():
    frame = samples.ethernet(samples.ROUTER_MAC, samples.OWN_MAC, 0x0800,
                             samples.ipv4("192.168.1.2", "8.8.8.8", 17, b"\x00" * 20, fragment_offset=185))

    info = parser.parse(frame, parser.LINK_ETHERNET)
    assert info.protocol == "UDP" and info.service_port is None
