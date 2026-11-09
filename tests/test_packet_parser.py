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


@pytest.mark.parametrize("frame", [b"", b"\x00" * 10, samples.https_out()[:20], samples.https_out()[:36]])
def test_cut_headers_are_counted_as_malformed_without_an_exception(frame):
    info = parser.parse(frame, parser.LINK_ETHERNET, original_length=60)

    assert info.malformed
    assert info.length == 60


def test_raw_ip_and_linux_cooked_captures_are_understood():
    raw = samples.ipv4("192.168.1.2", "192.168.1.1", 17, samples.udp(53001, 53))
    cooked = struct.pack("!HHH8sH", 0, 1, 6, samples.OWN_MAC + b"\x00\x00", 0x0800) + raw

    assert parser.parse(raw, parser.LINK_RAW).protocol == "DNS"
    assert parser.parse(cooked, parser.LINK_LINUX_SLL).protocol == "DNS"


def test_an_unknown_link_type_is_other_not_an_error():
    assert parser.parse(b"\x01\x02\x03", 127).protocol == "OTHER"


@pytest.mark.parametrize("source, destination, expected", [
    (51234, 443, 443), (443, 51234, 443), (53, 5353, 53), (50000, 60000, None), (0, 80, 80),
])
def test_the_service_port_is_the_known_one_of_the_conversation(source, destination, expected):
    assert parser.service_port(source, destination) == expected


def test_every_label_is_one_the_server_accepts():
    frames = [samples.https_out(), samples.dns_query(), samples.mdns(), samples.dhcp_discover(),
              samples.arp_request(), samples.icmpv6_multicast()]
    for frame in frames:
        assert parser.parse(frame, parser.LINK_ETHERNET).protocol in parser.PROTOCOLS
