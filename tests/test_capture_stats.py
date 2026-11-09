"""Lo único que sale de una captura: conteos que cuadran, dentro de los límites, sin direcciones."""
import json

import pytest

from agent import packet_parser as parser
from agent.capture_stats import CaptureStats, Limits, failure, local_networks
from tests import capture_samples as samples

OWN = frozenset({"192.168.1.2"})
LAN = local_networks(["192.168.1.2/24"])


def stats(seconds=30, packets=1000, bytes_=10_000_000) -> CaptureStats:
    return CaptureStats(Limits(seconds, packets, bytes_), OWN, LAN)


def add(s: CaptureStats, frame: bytes, at: float) -> bool:
    return s.add(parser.parse(frame, parser.LINK_ETHERNET), at)


def recorder_check(result: dict, limits: Limits) -> None:
    """Las mismas reglas que CaptureRecorder.check en el backend: lo que no cuadre, el servidor lo rechaza."""
    packets, size = result["packetCount"], result["byteCount"]
    assert packets <= limits.packets and size <= limits.bytes
    assert result.get("broadcastPackets", 0) + result.get("multicastPackets", 0) <= packets
    assert result.get("malformedPackets", 0) <= packets
    assert result.get("inboundBytes", 0) + result.get("outboundBytes", 0) <= size
    names = [p["protocol"] for p in result["protocols"]]
    assert len(names) == len(set(names)) and sum(p["packets"] for p in result["protocols"]) <= packets
    services = [(p["transport"], p["port"]) for p in result["ports"]]
    assert len(services) == len(set(services)) and sum(p["packets"] for p in result["ports"]) <= packets
    seconds = [i["second"] for i in result["intervals"]]
    assert len(seconds) == len(set(seconds)) and all(0 <= s <= 360 for s in seconds)
    assert sum(i["packets"] for i in result["intervals"]) <= packets


def test_a_capture_counts_protocols_directions_and_seconds_without_any_address():
    s = stats()
    for at, frame in [(100.0, samples.https_out()), (100.4, samples.https_in()), (101.2, samples.dns_query()),
                      (101.5, samples.arp_request()), (102.9, samples.mdns()), (102.95, samples.dhcp_discover())]:
        assert add(s, frame, at)

    result = s.result(9, "NPCAP", "Intel Wi-Fi 6", "2.0.0", 30_000, 2)

    assert result["packetCount"] == 6
    assert {p["protocol"]: p["packets"] for p in result["protocols"]} == {
        "HTTPS": 2, "DNS": 1, "ARP": 1, "MDNS": 1, "DHCP": 1}
    assert result["broadcastPackets"] == 2 and result["multicastPackets"] == 1
    assert result["outboundBytes"] == len(samples.https_out()) + len(samples.dns_query())  # ARP no lleva IP
    assert result["inboundBytes"] == len(samples.https_in())
    assert result["distinctRemoteHosts"] == 1 and result["distinctLocalHosts"] >= 2
    assert [i["second"] for i in result["intervals"]] == [0, 1, 2]
    assert {(p["transport"], p["port"]) for p in result["ports"]} >= {("TCP", 443), ("UDP", 53)}
    assert result["droppedByTool"] == 2 and result["stopReason"] == "DURATION"
    text = json.dumps(result)
    assert "192.168" not in text and "142.250" not in text and "secreto" not in text
    recorder_check(result, s.limits)


def test_the_packet_limit_stops_the_capture_and_says_so():
    s = stats(packets=2)
    assert add(s, samples.https_out(), 1.0) and add(s, samples.https_in(), 1.1)
    assert not add(s, samples.dns_query(), 1.2)

    assert s.full() and s.stop_reason == "PACKET_LIMIT"
    assert s.result(1, "PKTMON", None, "2.0.0", 1000, None)["packetCount"] == 2


def test_the_byte_limit_stops_before_going_over():
    s = stats(bytes_=len(samples.https_out()) + 10)
    assert add(s, samples.https_out(), 1.0)
    assert not add(s, samples.https_in(), 1.1)

    assert s.stop_reason == "BYTE_LIMIT"
    assert s.bytes <= s.limits.bytes


def test_packets_after_the_duration_are_not_counted():
    s = stats(seconds=5)
    assert add(s, samples.arp_request(), 50.0)
    assert not add(s, samples.arp_request(), 55.0)

    assert s.stop_reason == "DURATION" and s.packets == 1
