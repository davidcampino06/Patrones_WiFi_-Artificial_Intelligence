"""Reconocer los equipos (agente 1.7.0 y 1.8.0): lo que anuncian por mDNS y UPnP, sus puertos, el tipo que se deduce y
el nombre que dicen al pedir dirección por DHCP."""
import socket
import struct

from agent import device_discovery as discovery
from agent import wifisense_agent as agent


def name(text: str) -> bytes:
    return discovery.dns_name(text)


def record(owner: str, rtype: int, rdata: bytes) -> bytes:
    return name(owner) + struct.pack("!HHIH", rtype, 0x8001, 120, len(rdata)) + rdata


def txt(**values: str) -> bytes:
    return b"".join(bytes([len(f"{k}={v}".encode())]) + f"{k}={v}".encode() for k, v in values.items())


def response(*records: bytes) -> bytes:
    return struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


IPHONE = response(
    record("_companion-link._tcp.local", discovery.DNS_PTR, name("iPhone de Ana._companion-link._tcp.local")),
    record("iPhone de Ana._companion-link._tcp.local", discovery.DNS_TXT, txt(rpmd="iPhone15,2")),
    record("iPhone-de-Ana.local", discovery.DNS_A, socket.inet_aton("192.168.1.23")),
)
CHROMECAST = response(
    record("_googlecast._tcp.local", discovery.DNS_PTR, name("Chromecast-9f1c._googlecast._tcp.local")),
    record("Chromecast-9f1c._googlecast._tcp.local", discovery.DNS_TXT, txt(fn="Sala TV", md="Chromecast")),
)
PRINTER = response(
    record("_ipp._tcp.local", discovery.DNS_PTR, name("EPSON L3250 Series._ipp._tcp.local")),
    record("EPSON L3250 Series._ipp._tcp.local", discovery.DNS_TXT, txt(ty="EPSON L3250 Series")),
)


def test_the_mdns_query_asks_every_service_with_the_unicast_bit():
    query = discovery.mdns_browse_query(["_googlecast._tcp.local", "_ipp._tcp.local"])
    assert struct.unpack_from("!H", query, 4)[0] == 2
    assert query.endswith(struct.pack("!HH", discovery.DNS_PTR, 0x8001))
    assert b"\x0b_googlecast\x04_tcp\x05local\x00" in query


def test_what_devices_announce_gives_their_name_model_and_kind():
    found = discovery.mdns_identity([("192.168.1.23", IPHONE), ("192.168.1.40", CHROMECAST),
                                     ("192.168.1.50", PRINTER), ("192.168.1.60", b"\x00\x01garbage")])
    assert found["192.168.1.23"] == {"name": "iPhone de Ana", "model": "iPhone15,2"}
    assert found["192.168.1.40"] == {"name": "Sala TV", "model": "Chromecast", "kinds": ["TV"]}
    assert found["192.168.1.50"]["name"] == "EPSON L3250 Series"
    assert found["192.168.1.50"]["kinds"] == ["PRINTER"]
    assert "192.168.1.60" not in found  # a broken packet says nothing


def test_upnp_describes_tvs_and_consoles():
    xml = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
      <friendlyName>[TV] Samsung 7 Series (55)</friendlyName><manufacturer>Samsung Electronics</manufacturer>
      <modelName>UN55TU7000</modelName></device></root>"""
    assert discovery.parse_upnp_description(xml) == {
        "name": "[TV] Samsung 7 Series (55)", "model": "Samsung Electronics UN55TU7000", "kinds": ["TV"]}
    assert discovery.parse_upnp_description("<no-xml") == {}
    assert discovery.parse_ssdp_location(b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.7:8000/desc.xml\r\n\r\n") \
        == "http://192.168.1.7:8000/desc.xml"


def test_a_description_is_read_only_from_the_same_device_in_the_local_network():
    assert discovery.fetch_description("http://8.8.8.8/desc.xml", "8.8.8.8") == {}
    assert discovery.fetch_description("http://192.168.1.9/desc.xml", "192.168.1.7") == {}


def test_open_ports_suggest_the_kind_but_never_scan_the_router_or_this_computer(monkeypatch):
    probed = []

    def fake_open(ip, port, timeout=0.4):
        probed.append((ip, port))
        return (ip, port) in {("192.168.1.30", 62078), ("192.168.1.31", 554), ("192.168.1.31", 80)}
    monkeypatch.setattr(discovery, "port_open", fake_open)

    kinds = discovery.port_kinds(["192.168.1.1", "192.168.1.2", "192.168.1.30", "192.168.1.31", "8.8.8.8"],
                                 skip=["192.168.1.1", "192.168.1.2"])

    assert kinds == {"192.168.1.30": ["PHONE"], "192.168.1.31": ["CAMERA"]}
    assert {ip for ip, _ in probed} == {"192.168.1.30", "192.168.1.31"}


def test_the_kind_comes_from_the_name_then_the_services_then_the_maker():
    assert discovery.decide_kind("Galaxy-A54", None, None, ["TV"], True) == "PHONE"
    assert discovery.decide_kind(None, "MacBookPro18,1", "Apple", [], False) == "COMPUTER"
    assert discovery.decide_kind(None, None, None, ["TV", "TV", "SPEAKER"], False) == "TV"
    assert discovery.decide_kind(None, None, "Nintendo", [], False) == "CONSOLE"
    assert discovery.decide_kind(None, None, "Hikvision", [], False) == "CAMERA"
    assert discovery.decide_kind(None, None, None, [], True) == "PHONE"   # private MAC and nothing else
    assert discovery.decide_kind(None, None, "Intel", [], False) is None


def test_the_agent_sends_name_model_kind_and_role_but_never_the_mac():
    phone = agent.describe_device("192.168.1.23", "da:a1:19:00:00:01", "sal", "192.168.1.2", "192.168.1.1", None,
                                  {"name": "iPhone de Ana", "model": "iPhone15,2", "kinds": []})
    router = agent.describe_device("192.168.1.1", "50:c7:bf:00:00:02", "sal", "192.168.1.2", "192.168.1.1", None, {})
    itself = agent.describe_device("192.168.1.2", "3c:97:0e:00:00:03", "sal", "192.168.1.2", "192.168.1.1",
                                   "PC-JAIDER", {})

    assert phone == {"id": agent.mac_fingerprint("da:a1:19:00:00:01", "sal"), "privateMac": True,
                     "name": "iPhone de Ana", "model": "iPhone15,2", "kind": "PHONE"}
    assert router["role"] == "ROUTER" and "kind" not in router
    assert itself["role"] == "SELF" and itself["kind"] == "COMPUTER" and itself["name"] == "PC-JAIDER"
    assert "da:a1:19" not in str(phone)


def test_the_network_is_asked_again_only_every_half_hour_or_when_a_device_appears(monkeypatch):
    monkeypatch.setattr(agent, "_identity_cache", {"at": 0.0, "macs": frozenset(), "by_mac": {}})
    calls = []

    def identify(ips, own_ip, gateway):
        calls.append(sorted(ips))
        return {ip: {"name": f"equipo {ip[-1]}"} for ip in ips}
    devices = {"192.168.1.5": "aa:00:00:00:00:05"}

    assert agent.identities(devices, "192.168.1.2", "192.168.1.1", now=1000, identify=identify) == {
        "aa:00:00:00:00:05": {"name": "equipo 5"}}
    agent.identities(devices, "192.168.1.2", "192.168.1.1", now=1600, identify=identify)
    assert len(calls) == 1
    agent.identities({**devices, "192.168.1.6": "aa:00:00:00:00:06"}, "192.168.1.2", "192.168.1.1", now=1700,
                     identify=identify)
    agent.identities(devices, "192.168.1.2", "192.168.1.1", now=1700 + agent.IDENTITY_MAX_AGE + 1, identify=identify)
    assert len(calls) == 3


def test_while_someone_identifies_a_device_the_agent_reports_every_minute():
    assert agent.next_wait({"nextReportSeconds": 60}, 300) == 60
    assert agent.next_wait({"nextReportSeconds": 5}, 300) == agent.MIN_INTERVAL
    assert agent.next_wait({"nextReportSeconds": 900}, 300) == 300
    assert agent.next_wait({"summary": "ok"}, 300) == 300
    assert agent.next_wait(None, 300) == 300


def test_the_report_lists_the_devices_it_recognized():
    text = agent.describe({"deviceCount": 2, "openPorts": [], "devices": [
        {"id": "a" * 24, "name": "Sala TV", "kind": "TV"}, {"id": "b" * 24}]})
    assert "Equipos reconocidos: Sala TV (televisor)" in text


# ----------------------------------------------------------------------------------------------------- DHCP (1.8.0)

def dhcp_request(mac: str, *options: tuple[int, bytes], op: int = 1) -> bytes:
    """A DHCP request as a phone sends it when it joins the network (BOOTP header, magic cookie and options)."""
    header = bytes([op, 1, 6, 0]) + b"\x12\x34\x56\x78" + b"\x00" * 20 + bytes.fromhex(mac.replace(":", "")) \
        + b"\x00" * 10 + b"\x00" * 192
    body = b"".join(bytes([code, len(value)]) + value for code, value in options)
    return header + discovery.DHCP_MAGIC + bytes([53, 1, 3]) + body + b"\xff"


def test_a_dhcp_request_gives_the_mac_the_name_and_the_vendor_class():
    packet = dhcp_request("da:a1:19:00:00:01", (12, b"Galaxy-A54-de-Ana"), (60, b"android-dhcp-14"))

    assert discovery.parse_dhcp_request(packet) == {
        "mac": "da:a1:19:00:00:01", "name": "Galaxy-A54-de-Ana", "vendorClass": "android-dhcp-14"}
    assert discovery.dhcp_kind("android-dhcp-14") == "PHONE"
    assert discovery.dhcp_kind("MSFT 5.0") == "COMPUTER"


def test_the_fqdn_option_names_a_device_without_option_12():
    wire = b"\x04\x00\x00" + bytes([12]) + b"DESKTOP-7Q2M" + bytes([4]) + b"home" + b"\x00"  # formato DNS (bandera E)
    text = b"\x00\x00\x00" + b"PC-SALA.casa.lan"

    assert discovery.parse_dhcp_request(dhcp_request("3c:97:0e:00:00:03", (81, wire)))["name"] == "DESKTOP-7Q2M"
    assert discovery.parse_dhcp_request(dhcp_request("3c:97:0e:00:00:03", (81, text)))["name"] == "PC-SALA"


def test_generic_names_and_other_packets_are_ignored():
    generic = dhcp_request("da:a1:19:00:00:01", (12, b"android-5f3a9c0e21b4d7aa"))
    reply = dhcp_request("da:a1:19:00:00:01", (12, b"router"), op=2)

    assert "name" not in discovery.parse_dhcp_request(generic)
    assert discovery.parse_dhcp_request(reply) is None  # una respuesta del servidor, no un equipo
    assert discovery.parse_dhcp_request(b"\x01" * 100) is None


def test_the_watcher_remembers_each_device_and_keeps_its_name():
    watcher = discovery.DhcpWatcher()
    watcher.learn(dhcp_request("da:a1:19:00:00:01", (12, b"iPhone-de-Ana")))
    watcher.learn(dhcp_request("da:a1:19:00:00:01", (60, b"apple")))  # una renovación sin nombre no lo borra
    watcher.learn(b"basura")

    assert watcher.snapshot() == {"da:a1:19:00:00:01": {"name": "iPhone-de-Ana", "vendorClass": "apple"}}
