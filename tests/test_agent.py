"""The agent runs on the user's computer; these tests cover what it reads from the system and what it sends."""
import io
import json
import os
import urllib.error

import pytest

from agent import wifisense_agent as agent

NETSH_ES = """
Hay 1 interfaz en el sistema:

    Nombre                 : Wi-Fi
    Descripción            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 0b5c6c3e-0000-0000-0000-000000000000
    Dirección física       : 4c:79:6e:00:00:01
    Tipo de interfaz       : Principal
    Estado                 : conectado
    SSID                   : Casa_Lopez
    AP BSSID               : 9c:a2:f4:00:00:02
    Banda                  : 5 GHz
    Canal                  : 44
    Tipo de radio          : 802.11ac
    Autenticación          : WPA2-Personal
    Cifrado                : CCMP
    Modo de conexión       : Conexión automática
    Velocidad de recepción (Mbps)  : 433.3
    Velocidad de transmisión (Mbps) : 390
    Señal                  : 82%
    Perfil                 : Casa_Lopez
"""

NETSH_EN_WEP = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : OldRouter
    BSSID                  : 00:11:22:33:44:55
    Radio type             : 802.11g
    Authentication         : Open
    Cipher                 : WEP
    Channel                : 6
    Receive rate (Mbps)    : 54
    Transmit rate (Mbps)   : 54
    Signal                 : 40%
    Rssi                   : -71
"""

NETSH_NETWORKS = """
SSID 1 : Casa_Lopez
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Personal
    BSSID 1                 : 9c:a2:f4:00:00:02
         Señal             : 82%
         Canal            : 44
    BSSID 2                 : 9c:a2:f4:00:00:03
         Canal            : 6
SSID 2 : Vecino_1
    BSSID 1                 : aa:bb:cc:00:00:01
         Canal            : 44
SSID 3 : Vecino_2
    BSSID 1                 : aa:bb:cc:00:00:02
         Canal            : 6
SSID 4 :
    BSSID 1                 : aa:bb:cc:00:00:03
         Canal            : 44
"""


def test_reads_wifi_from_spanish_netsh():
    info = agent.parse_netsh_interfaces(NETSH_ES)

    assert info["ssid"] == "Casa_Lopez"
    assert info["authentication"] == "WPA2"
    assert info["cipher"] == "CCMP"
    assert info["band"] == "5"
    assert info["channel"] == 44
    assert info["signalPercent"] == 82
    assert info["signalDbm"] == -59
    assert info["rxRateMbps"] == 433.3
    assert info["txRateMbps"] == 390


def test_reads_wifi_from_english_netsh_and_prefers_rssi():
    info = agent.parse_netsh_interfaces(NETSH_EN_WEP)

    assert info["authentication"] == "WEP"
    assert info["signalDbm"] == -71
    assert info["band"] == "2.4"


def test_netsh_without_wifi_or_permission_returns_nothing():
    assert agent.parse_netsh_interfaces("Hay 0 interfaces en el sistema.") == {}


def test_counts_neighbors_on_the_same_channel_excluding_own_network():
    networks = agent.parse_netsh_networks(NETSH_NETWORKS)

    assert agent.neighbors_on_channel(networks, "Casa_Lopez", 44) == (2, 3)


@pytest.mark.parametrize("auth, cipher, expected", [
    ("WPA3-Personal", "GCMP", "WPA3"), ("WPA2-Personal", "CCMP", "WPA2"), ("WPA-Personal", "TKIP", "WPA"),
    ("Abierta", "WEP", "WEP"), ("Abierta", "Ninguno", "OPEN"), ("Open", "None", "OPEN"),
    ("WPA2 WPA3", "", "WPA3"), ("", "", "UNKNOWN"),
])
def test_authentication_mapping(auth, cipher, expected):
    assert agent.authentication_of(auth, cipher) == expected


def test_reads_wifi_from_nmcli_with_escaped_colons():
    text = ("no:Vecino:6:2437 MHz:60:WPA2:130 Mbit/s\n"
            "yes:Mi\\:Red:36:5180 MHz:74:WPA2 WPA3:866 Mbit/s\n"
            "no:Otro:36:5180 MHz:30:WPA1:54 Mbit/s\n")

    info, networks = agent.parse_nmcli(text)

    assert info["ssid"] == "Mi:Red"
    assert info["authentication"] == "WPA3"
    assert info["band"] == "5"
    assert info["signalDbm"] == -63
    assert agent.neighbors_on_channel(networks, "Mi:Red", 36) == (1, 2)


def test_default_gateway_on_windows_takes_the_lowest_metric():
    text = """
IPv4 Tabla de enrutamiento
Rutas activas:
Destino de red        Máscara de red   Puerta de enlace   Interfaz  Métrica
          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.23     50
          0.0.0.0          0.0.0.0      10.10.0.1      10.10.0.5        25
"""
    assert agent.parse_route_print(text) == "10.10.0.1"


def test_default_gateway_on_linux():
    text = ("Iface\tDestination\tGateway \tFlags\n"
            "wlan0\t0000A8C0\t00000000\t0001\n"
            "wlan0\t00000000\t0101A8C0\t0003\n")
    assert agent.parse_proc_route(text) == "192.168.1.1"


def test_arp_table_on_windows_keeps_only_real_devices():
    text = """
Interfaz: 192.168.1.23 --- 0xb
  Dirección de Internet          Dirección física      Tipo
  192.168.1.1           9c-a2-f4-00-00-02     dinámico
  192.168.1.40          D2-11-22-33-44-55     dinámico
  192.168.1.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
  10.0.0.9              aa-aa-aa-aa-aa-aa     dinámico
"""
    table = agent.same_subnet(agent.parse_neighbors(text), "192.168.1.23")

    assert table == {"192.168.1.1": "9c:a2:f4:00:00:02", "192.168.1.40": "d2:11:22:33:44:55"}


def test_arp_table_on_linux_skips_incomplete_entries():
    text = ("IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         9c:a2:f4:00:00:02     *        wlan0\n"
            "192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        wlan0\n")
    assert agent.parse_neighbors(text) == {"192.168.1.1": "9c:a2:f4:00:00:02"}


def test_mac_fingerprints_do_not_reveal_the_mac_and_depend_on_the_salt():
    one = agent.mac_fingerprint("9C:A2:F4:00:00:02", "sal-1")

    assert one == agent.mac_fingerprint("9c:a2:f4:00:00:02", "sal-1")
    assert one != agent.mac_fingerprint("9c:a2:f4:00:00:02", "sal-2")
    assert "9ca2f4" not in one
    assert len(one) == 24


def test_latency_summary_counts_silence_as_loss():
    samples = [10.0, 12.0, None, 11.0, None]

    assert agent.summarize(samples) == {"latencyMs": 11.0, "jitterMs": 1.5, "packetLossPct": 40.0}
    assert agent.summarize([None, None])["latencyMs"] is None


def test_measure_uses_the_probe(monkeypatch):
    monkeypatch.setattr(agent.time, "sleep", lambda _: None)
    values = iter([20.0, 22.0, 21.0])

    result = agent.measure("1.1.1.1", 443, count=3, probe=lambda host, port: next(values))

    assert result["latencyMs"] == 21.0
    assert result["packetLossPct"] == 0.0


def test_report_leaves_out_what_could_not_be_measured():
    report = agent.build_report({"ssid": "Casa", "authentication": "WPA2", "channel": 6},
                                {"latencyMs": 20.0, "jitterMs": 2.0, "packetLossPct": 0.0}, None,
                                [{"id": "a" * 24, "vendor": "Apple", "name": "iPhone"}, {"id": "b" * 24}], [80, 443])

    assert report["deviceCount"] == 2
    assert report["deviceHashes"] == ["a" * 24, "b" * 24]
    assert report["devices"] == [{"id": "a" * 24, "vendor": "Apple", "name": "iPhone"}, {"id": "b" * 24}]
    assert report["openPorts"] == [80, 443]
    assert "gatewayLatencyMs" not in report
    assert "signalDbm" not in report
    assert report["agentVersion"] == agent.AGENT_VERSION


@pytest.mark.parametrize("mac, vendor", [
    ("FC:FB:FB:11:22:33", "Apple"), ("ec:fa:bc:00:11:22", "Samsung"), ("b8-27-eb-aa-bb-cc", "Raspberry Pi"),
    ("5c:62:8b:00:00:01", "TP-Link"), ("00:11:22:33:44:55", None),
])
def test_vendor_comes_from_the_mac_oui(mac, vendor):
    assert agent.vendor_of(mac) == vendor


class QuietDhcp:
    """Stands in for the DHCP listener: it never opens port 67 and knows the names it is given."""

    def __init__(self, seen=None):
        self.seen = seen or {}

    def start(self):
        return False

    def snapshot(self):
        return dict(self.seen)


def test_devices_carry_a_fingerprint_vendor_and_name(monkeypatch):
    monkeypatch.setattr(agent, "wake_neighbors", lambda ip: None)
    monkeypatch.setattr(agent.time, "sleep", lambda _s: None)
    monkeypatch.setattr(agent, "identities", lambda *args, **kwargs: {})  # no real mDNS, UPnP or port probes
    monkeypatch.setattr(agent.discovery, "DHCP", QuietDhcp())  # no real DHCP listener in the tests
    monkeypatch.setattr(agent, "IS_WINDOWS", False)
    monkeypatch.setattr(agent, "read_file", lambda _p: (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.5      0x1         0x2         fc:fb:fb:11:22:33     *        wlan0\n"
        "192.168.1.9      0x1         0x2         00:11:22:33:44:55     *        wlan0\n"))
    monkeypatch.setattr(agent, "own_mac", lambda: None)
    monkeypatch.setattr(agent, "hostname_of", lambda ip: {"192.168.1.5": "iPhone-de-Ana"}.get(ip))

    found = agent.devices("192.168.1.2", "sal", wait=0)

    by_vendor = {d.get("vendor"): d for d in found}
    assert len(found) == 2
    assert by_vendor["Apple"]["id"] == agent.mac_fingerprint("fc:fb:fb:11:22:33", "sal")
    assert by_vendor["Apple"]["name"] == "iPhone-de-Ana"
    assert None in by_vendor  # el equipo sin OUI conocido no lleva fabricante
    assert "name" not in by_vendor[None]  # tampoco nombre si nadie respondió
    assert all("fc:fb:fb" not in device["id"] for device in found)  # la MAC nunca viaja


@pytest.mark.parametrize("raw, ip, expected", [
    ("iPhone-de-Ana.lan", "192.168.1.5", "iPhone-de-Ana"), ("PC-SALA.local.", "192.168.1.6", "PC-SALA"),
    ("galaxy-s21", "192.168.1.7", "galaxy-s21"), ("192.168.1.8", "192.168.1.8", None),
    ("", "192.168.1.9", None), (None, "192.168.1.9", None),
])
def test_clean_hostname(raw, ip, expected):
    assert agent.clean_hostname(raw, ip) == expected


def test_netbios_name_reads_the_unique_entry(monkeypatch):
    output = (
        "Nombre            Tipo         Estado\n"
        "---------------------------------------------\n"
        "LAPTOP-ANA     <00>  UNIQUE      Registrado\n"
        "GRUPO_TRABAJO  <00>  GROUP       Registrado\n")
    monkeypatch.setattr(agent, "run_command", lambda *a, **k: output)
    assert agent.netbios_name("192.168.1.5") == "LAPTOP-ANA"


@pytest.mark.parametrize("mac, vendor", [
    ("f0:d7:aa:00:00:01", "Motorola"), ("10:68:2b:00:00:01", "Realme"), ("cc:6d:a0:00:00:01", "Roku"),
    ("a0:20:a6:00:00:01", "Espressif"), ("c4:e9:0a:00:00:01", "Mercusys"),
])
def test_vendor_table_covers_more_brands(mac, vendor):
    assert agent.vendor_of(mac) == vendor


def test_vendor_table_only_has_valid_ouis():
    assert len(agent.OUI_VENDORS) > 150
    assert all(len(oui) == 6 and int(oui, 16) >= 0 for oui in agent.OUI_VENDORS)


@pytest.mark.parametrize("mac, private", [
    ("da:a1:19:00:00:01", True),   # segundo bit del primer byte en 1: MAC aleatoria de un celular
    ("3e:22:fb:00:00:01", True), ("fc:fb:fb:11:22:33", False), ("00-11-22-33-44-55", False),
])
def test_detects_private_random_macs(mac, private):
    assert agent.is_private_mac(mac) is private


def test_devices_mark_private_macs_without_vendor(monkeypatch):
    monkeypatch.setattr(agent, "wake_neighbors", lambda ip: None)
    monkeypatch.setattr(agent.time, "sleep", lambda _s: None)
    monkeypatch.setattr(agent, "identities", lambda *args, **kwargs: {})  # no real mDNS, UPnP or port probes
    monkeypatch.setattr(agent.discovery, "DHCP", QuietDhcp())  # no real DHCP listener in the tests
    monkeypatch.setattr(agent, "IS_WINDOWS", False)
    monkeypatch.setattr(agent, "read_file", lambda _p: (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.5      0x1         0x2         da:a1:19:00:00:01     *        wlan0\n"
        "192.168.1.6      0x1         0x2         fc:fb:fb:11:22:33     *        wlan0\n"))
    monkeypatch.setattr(agent, "own_mac", lambda: None)
    monkeypatch.setattr(agent, "hostname_of", lambda ip: None)

    found = {d.get("vendor"): d for d in agent.devices("192.168.1.2", "sal", wait=0)}

    assert found[None]["privateMac"] is True
    assert "privateMac" not in found["Apple"]  # con fabricante conocido no hace falta


def mdns_answer(name: str) -> bytes:
    """Respuesta mDNS de ejemplo: la pregunta por 5.1.168.192.in-addr.arpa y un PTR que apunta a ella comprimida."""
    import struct
    question = agent.dns_name("5.1.168.192.in-addr.arpa")
    rdata = agent.dns_name(name)
    return (struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0) + question + struct.pack("!HH", 12, 1)
            + b"\xc0\x0c" + struct.pack("!HHIH", 12, 0x8001, 120, len(rdata)) + rdata)


def test_mdns_query_asks_for_the_reverse_name():
    query = agent.mdns_query("192.168.1.5")
    assert query[:12] == b"\0\0\0\0\0\x01\0\0\0\0\0\0"
    assert agent.dns_name("5.1.168.192.in-addr.arpa") in query
    assert query.endswith(b"\x00\x0c\x80\x01")  # PTR, clase IN con respuesta directa (QU)


def test_parse_mdns_ptr_follows_compression():
    assert agent.parse_mdns_ptr(mdns_answer("iPhone-de-Ana.local")) == "iPhone-de-Ana.local"


@pytest.mark.parametrize("packet", [b"", b"\0" * 12, agent.mdns_query("192.168.1.5")])
def test_parse_mdns_ptr_ignores_queries_and_garbage(packet):
    assert agent.parse_mdns_ptr(packet) is None


def test_mdns_name_sends_to_the_multicast_group(monkeypatch):
    sent = []

    class FakeSocket:
        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, _t):
            pass

        def sendto(self, data, address):
            sent.append(address)

        def recvfrom(self, _size):
            return mdns_answer("Chromecast-Sala.local"), ("192.168.1.5", 5353)

    monkeypatch.setattr(agent.socket, "socket", FakeSocket)

    assert agent.mdns_name("192.168.1.5") == "Chromecast-Sala"
    assert sent == [("224.0.0.251", 5353)]


def test_hostname_falls_back_to_mdns(monkeypatch):
    def no_dns(_ip):
        raise OSError("sin DNS inverso")

    monkeypatch.setattr(agent.socket, "gethostbyaddr", no_dns)
    monkeypatch.setattr(agent, "IS_WINDOWS", False)
    monkeypatch.setattr(agent, "mdns_name", lambda ip, timeout=1.0: "MacBook-de-Luis")

    assert agent.hostname_of("192.168.1.8") == "MacBook-de-Luis"


def test_channel_counts_exclude_own_network_and_sort():
    networks = [("Casa", 6), ("Vecino", 6), ("Vecino", 6), ("Tienda", 1), ("Otro", 11), ("Raro", 0)]
    assert agent.channel_counts(networks, "Casa") == [
        {"channel": 1, "networks": 1}, {"channel": 6, "networks": 2}, {"channel": 11, "networks": 1}]


def test_report_carries_the_channel_counts():
    report = agent.build_report({"ssid": "Casa", "channel": 6, "channelCounts": [{"channel": 6, "networks": 3}]},
                                {}, None, [], [])
    assert report["channelCounts"] == [{"channel": 6, "networks": 3}]
    assert "channelCounts" not in agent.build_report({"ssid": "Casa", "channelCounts": []}, {}, None, [], [])


@pytest.mark.parametrize("url, ok", [
    ("https://wifisense.example.com/", True), ("http://localhost:8099", True), ("http://127.0.0.1:8080", True),
    ("http://wifisense.example.com", False), ("ftp://localhost", False), ("https://", False),
])
def test_server_must_use_https_except_locally(url, ok):
    if ok:
        assert agent.validate_server(url).startswith(("https://", "http://"))
    else:
        with pytest.raises(ValueError):
            agent.validate_server(url)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def test_send_posts_json_with_the_agent_key():
    seen = {}

    def opener(request, timeout):
        seen.update(url=request.full_url, key=request.get_header("X-agent-key"), body=json.loads(request.data))
        return FakeResponse(b'{"summary": "ok"}')

    answer = agent.send({"deviceCount": 3}, "https://wifisense.example.com", "wsa_" + "x" * 43, opener=opener)

    assert answer == {"summary": "ok"}
    assert seen["url"] == "https://wifisense.example.com/api/agent/reports"
    assert seen["key"].startswith("wsa_")
    assert seen["body"] == {"deviceCount": 3}


@pytest.mark.parametrize("code, fatal, retry", [(401, True, None), (429, False, 60), (500, False, None)])
def test_send_errors(code, fatal, retry):
    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, code, "error", {}, None)

    with pytest.raises(agent.SendError) as error:
        agent.send({}, "https://wifisense.example.com", "wsa_" + "x" * 43, opener=opener)
    assert error.value.fatal is fatal
    assert error.value.retry_after == retry


def test_config_is_private_and_env_overrides(tmp_path, monkeypatch):
    path = tmp_path / "WiFiSense" / "agent.json"
    agent.save_config({"server": "https://a.example.com", "key": "wsa_" + "k" * 43, "salt": "s"}, path)

    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setenv("WIFISENSE_AGENT_KEY", "wsa_" + "e" * 43)
    config = agent.load_config(path)
    assert config["key"] == "wsa_" + "e" * 43
    assert config["server"] == "https://a.example.com"


def test_key_format():
    assert agent.KEY_PATTERN.match("wsa_" + "A1_-" * 11)
    assert not agent.KEY_PATTERN.match("wsa_corta")
    assert not agent.KEY_PATTERN.match("Bearer " + "x" * 40)


def test_salt_is_saved_without_writing_the_key_from_the_environment(tmp_path, monkeypatch):
    path = tmp_path / "agent.json"
    monkeypatch.setenv("WIFISENSE_AGENT_KEY", "wsa_" + "e" * 43)
    config = agent.load_config(path)

    salt = agent.ensure_salt(config, path)

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored == {"salt": salt}
    assert agent.ensure_salt(agent.load_config(path), path) == salt


def test_send_shows_why_the_server_rejected_the_report():
    body = io.BytesIO(json.dumps({"detail": "Revisa los datos ingresados.",
                                  "errors": {"neighborsTotal": "debe ser menor que o igual a 500"}}).encode())

    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", {}, body)

    with pytest.raises(agent.SendError) as error:
        agent.send({}, "https://wifisense.example.com", "wsa_" + "x" * 43, opener=opener)
    assert str(error.value) == ("el servidor respondió 400: Revisa los datos ingresados. | "
                                "neighborsTotal: debe ser menor que o igual a 500")


@pytest.mark.parametrize("text, expected", [
    ("CCMP", "CCMP"), ("GCMP-256", "GCMP-256"), ("TKIP", "TKIP"), ("Ninguno", "NONE"), ("", None),
    ("CCMP (cifrado de grupo: TKIP) Microsoft", "CCMP"), ("Algo desconocido y muy largo del fabricante", "Algo desconocido y m"),
])
def test_cipher_is_always_short(text, expected):
    assert agent.cipher_of(text) == expected
    assert expected is None or len(agent.cipher_of(text)) <= 20


# ------------------------------------------------------------------------------------------------------- tráfico

PROC_NET_DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 9000      90    0    0    0     0          0         0     9000      90    0    0    0     0       0          0
 wlan0: 5000000  4000    0    0    0     0          0         0  1000000   2500    0    0    0     0       0          0
docker0: 777777   777    0    0    0     0          0         0   777777    777    0    0    0     0       0          0
"""

PROC_NET_SNMP = """Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 6500
Icmp: InMsgs InErrors OutMsgs
Icmp: 12 0 10
Tcp: RtoAlgorithm RtoMin InSegs OutSegs
Tcp: 1 200 3000 2900
Udp: InDatagrams NoPorts InErrors OutDatagrams
Udp: 400 0 0 350
"""

PROC_NET_SNMP6 = """Udp6InDatagrams                 40
Udp6OutDatagrams                30
Icmp6InMsgs                     2
Icmp6OutMsgs                    1
Ip6InReceives                   99
"""


def test_linux_counters_skip_loopback_and_bridges():
    assert agent.parse_proc_net_dev(PROC_NET_DEV) == {
        "bytes.in": 5_000_000, "bytes.out": 1_000_000, "packets.in": 4000, "packets.out": 2500}
    assert agent.parse_proc_net_dev("") == {}


def test_linux_protocol_counters_include_ipv6():
    assert agent.parse_proc_net_snmp(PROC_NET_SNMP, PROC_NET_SNMP6) == {
        "ICMP.in4": 12, "ICMP.out4": 10, "TCP.in4": 3000, "TCP.out4": 2900, "UDP.in4": 400, "UDP.out4": 350,
        "UDP.in6": 40, "UDP.out6": 30, "ICMP.in6": 2, "ICMP.out6": 1}


def test_a_32_bit_protocol_counter_that_wraps_still_counts_but_a_reboot_does_not():
    assert agent.counter_delta(150, 100, "TCP.in4") == 50
    assert agent.counter_delta(10, 2 ** 32 - 90, "TCP.in4") == 100
    assert agent.counter_delta(10, 5_000, "TCP.in4") is None
    assert agent.counter_delta(10, 2 ** 32 - 90, "bytes.in") is None  # 64-bit: going back is a restart


def test_the_report_carries_the_traffic_since_the_previous_one():
    before = {"bytes.in": 1000, "bytes.out": 500, "packets.in": 10, "packets.out": 8, "TCP.in4": 100,
              "TCP.out4": 90, "UDP.in4": 5, "UDP.in6": 1, "ICMP.in4": 0}
    now = {"bytes.in": 5_243_880, "bytes.out": 1500, "packets.in": 4010, "packets.out": 108, "TCP.in4": 3100,
           "TCP.out4": 1090, "UDP.in4": 55, "UDP.in6": 3, "ICMP.in4": 0}
    fields = agent.traffic_fields({"at": 1000.0, "counters": before}, now, now=1300.0)
    assert fields == {"trafficBytes": 5_243_880, "trafficPackets": 4100,
                      "protocolPackets": [{"protocol": "TCP", "packets": 4000}, {"protocol": "UDP", "packets": 52},
                                          {"protocol": "ICMP", "packets": 0}]}


def test_no_traffic_the_first_time_after_a_long_pause_or_a_restart():
    counters = {"bytes.in": 10, "bytes.out": 10, "packets.in": 1, "packets.out": 1}
    assert agent.traffic_fields(None, counters, now=1000.0) == {}
    assert agent.traffic_fields({"at": 0.0, "counters": counters}, counters, now=10_000.0) == {}
    restarted = dict(counters, **{"bytes.in": 1})
    assert agent.traffic_fields({"at": 900.0, "counters": counters}, restarted, now=1000.0) == {}
    assert agent.traffic_fields({"at": 900.0, "counters": counters}, {}, now=1000.0) == {}


def test_the_counters_are_kept_only_after_the_report_arrived(tmp_path, monkeypatch):
    state = tmp_path / "traffic.json"
    monkeypatch.setattr(agent, "traffic_state_path", lambda: state)
    monkeypatch.setattr(agent, "load_config", lambda: {"key": "wsa_" + "k" * 43, "server": "https://x.example"})
    monkeypatch.setattr(agent, "ensure_salt", lambda config: "sal")
    monkeypatch.setattr(agent, "collect", lambda salt: {"deviceCount": 0, "openPorts": []})
    monkeypatch.setattr(agent, "traffic_counters", lambda: {"bytes.in": 1, "bytes.out": 1, "packets.in": 1,
                                                            "packets.out": 1})

    def refused(report, server, key):
        raise agent.SendError("sin conexión")
    monkeypatch.setattr(agent, "send", refused)
    assert agent.command_run(agent.argparse.Namespace(once=True, interval=300)) == 1
    assert not state.exists()

    monkeypatch.setattr(agent, "send", lambda report, server, key: {"summary": "ok"})
    assert agent.command_run(agent.argparse.Namespace(once=True, interval=300)) == 0
    assert agent.load_traffic_state(state)["counters"] == {"bytes.in": 1, "bytes.out": 1, "packets.in": 1,
                                                           "packets.out": 1}


@pytest.mark.skipif(os.name != "nt", reason="la API IP Helper solo existe en Windows")
def test_windows_reads_its_own_counters():
    counters = agent.windows_counters()
    assert counters, "la estructura MIB_IF_ROW2 no coincide o la API no respondió"
    assert counters["TCP.in4"] >= 0 and counters["UDP.out4"] >= 0
    assert {"bytes.in", "bytes.out", "packets.in", "packets.out"} <= counters.keys()


# --------------------------------------------------------------------------------- varias redes por Wi-Fi (1.6.0)

CASA, LAB = "wsa_" + "c" * 43, "wsa_" + "l" * 43


def test_a_code_is_tied_to_the_wifi_and_codes_of_other_wifis_are_kept(tmp_path, monkeypatch):
    monkeypatch.delenv("WIFISENSE_AGENT_KEY", raising=False)
    path = tmp_path / "agent.json"
    agent.save_pairing({"key": CASA, "networkName": "Casa"}, "https://x.example.com", path, ssid="Casa-5G")
    agent.save_pairing({"key": LAB, "networkName": "Lab"}, "https://x.example.com", path, ssid="Lab-Redes")
    new_casa = "wsa_" + "n" * 43
    agent.save_pairing({"key": new_casa, "networkName": "Casa"}, "https://x.example.com", path, ssid="Casa-5G")

    networks = agent.config_networks(agent.load_config(path))
    assert networks == [{"key": LAB, "network": "Lab", "ssid": "Lab-Redes"},
                        {"key": new_casa, "network": "Casa", "ssid": "Casa-5G"}]
    assert agent.describe_networks(networks) == "«Lab» en Lab-Redes; «Casa» en Casa-5G"


def test_the_wifi_decides_which_network_receives_the_report():
    networks = [{"key": CASA, "network": "Casa", "ssid": "Casa-5G"}, {"key": LAB, "network": "Lab", "ssid": "Lab-Redes"}]
    assert agent.choose_network(networks, "Lab-Redes")["key"] == LAB
    assert agent.choose_network(networks, "Casa-5G")["key"] == CASA
    assert agent.choose_network(networks, "Cafe-Gratis") is None   # a Wi-Fi without code: nothing is sent
    assert agent.choose_network(networks, None) is None            # cannot tell which one
    single = [{"key": CASA, "network": "Casa", "ssid": "Casa-5G"}]
    assert agent.choose_network(single, None)["key"] == CASA       # by cable, with only one network
    assert agent.choose_network(single, "Otra") is None


def test_an_installation_before_1_6_keeps_working_and_learns_its_wifi(tmp_path, monkeypatch):
    monkeypatch.delenv("WIFISENSE_AGENT_KEY", raising=False)
    path = tmp_path / "agent.json"
    agent.save_config({"server": "https://x.example.com", "key": CASA, "network": "Casa", "salt": "s"}, path)

    networks = agent.config_networks(agent.load_config(path))
    chosen = agent.choose_network(networks, "Casa-5G")
    assert chosen["key"] == CASA
    agent.learn_ssid(chosen, "Casa-5G", path)

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert "key" not in stored and stored["salt"] == "s"
    assert stored["networks"] == [{"key": CASA, "network": "Casa", "ssid": "Casa-5G"}]
    assert agent.choose_network(agent.config_networks(stored), "Otra") is None


def test_the_agent_switches_network_with_the_wifi_and_a_revoked_key_is_dropped(tmp_path, monkeypatch):
    monkeypatch.delenv("WIFISENSE_AGENT_KEY", raising=False)
    path = tmp_path / "agent.json"
    agent.save_pairing({"key": CASA, "networkName": "Casa"}, "https://x.example.com", path, ssid="Casa-5G")
    agent.save_pairing({"key": LAB, "networkName": "Lab"}, "https://x.example.com", path, ssid="Lab-Redes")
    original_load = agent.load_config
    monkeypatch.setattr(agent, "config_path", lambda: path)
    monkeypatch.setattr(agent, "load_config", lambda path_=None: original_load(path))
    monkeypatch.setattr(agent, "traffic_state_path", lambda: tmp_path / "traffic.json")
    monkeypatch.setattr(agent, "traffic_counters", lambda: {})
    wifi = {"ssid": "Lab-Redes"}
    monkeypatch.setattr(agent, "collect", lambda salt: {"ssid": wifi["ssid"], "deviceCount": 0, "openPorts": []})
    sent = []

    def send(report, server, key):
        sent.append(key)
        if key == CASA:
            raise agent.SendError("la clave fue revocada", fatal=True)
        return {"summary": "ok"}
    monkeypatch.setattr(agent, "send", send)
    once = agent.argparse.Namespace(once=True, interval=300)

    assert agent.command_run(once) == 0
    wifi["ssid"] = "Casa-5G"
    assert agent.command_run(once) == 1
    assert sent == [LAB, CASA]
    # the revoked network is forgotten, the other one stays
    assert [n["key"] for n in agent.config_networks(original_load(path))] == [LAB]
    wifi["ssid"] = "Cafe-Gratis"
    assert agent.command_run(once) == 1 and sent == [LAB, CASA]


def test_traffic_is_not_mixed_between_two_networks(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFISENSE_AGENT_KEY", LAB)
    state = tmp_path / "traffic.json"
    monkeypatch.setattr(agent, "traffic_state_path", lambda: state)
    monkeypatch.setattr(agent, "ensure_salt", lambda config: "sal")
    monkeypatch.setattr(agent, "collect", lambda salt: {"deviceCount": 0, "openPorts": []})
    counters = {"bytes.in": 500, "bytes.out": 500, "packets.in": 5, "packets.out": 5}
    monkeypatch.setattr(agent, "traffic_counters", lambda: counters)
    reports = []
    monkeypatch.setattr(agent, "send", lambda report, server, key: reports.append(report) or {})
    agent.save_traffic_state({"bytes.in": 1, "bytes.out": 1, "packets.in": 1, "packets.out": 1}, state,
                             network=CASA[:12])

    agent.command_run(agent.argparse.Namespace(once=True, interval=300))

    assert "trafficBytes" not in reports[0]  # the previous counters were of the other network
    assert agent.load_traffic_state(state)["network"] == LAB[:12]


def test_the_name_a_phone_gave_when_asking_for_an_address_is_used(monkeypatch):
    monkeypatch.setattr(agent, "wake_neighbors", lambda ip: None)
    monkeypatch.setattr(agent.time, "sleep", lambda _s: None)
    monkeypatch.setattr(agent, "identities", lambda *args, **kwargs: {})
    monkeypatch.setattr(agent, "IS_WINDOWS", False)
    monkeypatch.setattr(agent, "read_file", lambda _p: (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.5      0x1         0x2         da:a1:19:00:00:01     *        wlan0\n"
        "192.168.1.6      0x1         0x2         fc:fb:fb:11:22:33     *        wlan0\n"))
    monkeypatch.setattr(agent, "own_mac", lambda: None)
    monkeypatch.setattr(agent, "hostname_of", lambda ip: {"192.168.1.6": "iphone-dns"}.get(ip))
    monkeypatch.setattr(agent.discovery, "DHCP", QuietDhcp({
        "da:a1:19:00:00:01": {"name": "Galaxy-A54-de-Ana", "vendorClass": "android-dhcp-14"},
        "fc:fb:fb:11:22:33": {"name": "iPhone-de-Luis"},
    }))

    found = {d.get("vendor"): d for d in agent.devices("192.168.1.2", "sal", wait=0)}

    assert found[None]["name"] == "Galaxy-A54-de-Ana"  # MAC privada: sin DHCP no tendría nombre
    assert found[None]["kind"] == "PHONE"
    assert found["Apple"]["name"] == "iPhone-de-Luis"  # lo que dice el equipo gana al DNS de la red
