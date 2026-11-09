"""Las herramientas de captura (Npcap, pktmon, sockets) con sus fallas, sin instalar ni ejecutar nada real en
Windows. La última prueba captura de verdad en Linux cuando el entorno lo permite (root y AF_PACKET)."""
import os
import socket
import subprocess
import threading
import time

import pytest

from agent import capture_backends as backends
from agent.capture_files import TempCapture, captures_dir
from agent.capture_stats import CaptureStats, Limits
from tests import capture_samples as samples


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def session(limits=Limits(5, 1000, 10_000_000), stop=lambda: False, temp=None, clock=None, own_ip="192.168.1.2"):
    clock = clock or FakeClock()
    return backends.Session(CaptureStats(limits, frozenset({own_ip})), stop, temp, own_ip, clock=clock.clock,
                            wall=lambda: 1000.0 + clock.now, sleep=clock.sleep)


# ------------------------------------------------------------------------------------------------------ Npcap

class FakeNpcap:
    """Los mismos métodos que NpcapLibrary, con paquetes de prueba y un reloj que avanza con cada lectura."""

    def __init__(self, clock, frames=(), open_error=None, fail_at=None, monitor=False):
        self.clock, self.frames, self.open_error, self.fail_at, self.monitor = clock, list(frames), open_error, \
            fail_at, monitor
        self.opened, self.closed, self.reads = None, False, 0

    def devices(self):
        return [backends.NpcapDevice(r"\Device\NPF_Loopback", "Adapter for loopback", [], True),
                backends.NpcapDevice(r"\Device\NPF_{ETH}", "Realtek PCIe GbE", ["10.0.0.5"]),
                backends.NpcapDevice(r"\Device\NPF_{WIFI}", "Intel(R) Wi-Fi 6 AX201", ["192.168.1.2"])]

    def open(self, name):
        if self.open_error:
            raise backends.CaptureFailed(backends._failure_of(self.open_error), self.open_error)
        self.opened = name
        return 7

    def datalink(self, handle):
        return 1

    def next(self, handle):
        self.reads += 1
        self.clock.now += 0.5
        if self.fail_at and self.reads >= self.fail_at:
            return -1, 0.0, b"", 0
        if self.frames:
            data = self.frames.pop(0)
            return 1, 1000.0 + self.clock.now, data[:backends.SNAPLEN], len(data)
        return 0, 0.0, b"", 0

    def error(self, handle):
        return "el adaptador se desconectó"

    def dropped(self, handle):
        return 3

    def close(self, handle):
        self.closed = True

    def can_monitor(self, name):
        return self.monitor


def test_npcap_captures_on_the_interface_that_has_this_computers_ip_and_reports_its_drops():
    clock = FakeClock()
    library = FakeNpcap(clock, [samples.https_out(), samples.dns_query(), samples.arp_request()])
    backend = backends.NpcapBackend(lambda: library)
    s = session(clock=clock)

    run = backend.capture(s)

    assert library.opened == r"\Device\NPF_{WIFI}"
    assert run.interface_name == "Intel(R) Wi-Fi 6 AX201" and run.dropped_by_tool == 3
    assert s.stats.packets == 3 and s.stats.stop_reason == "DURATION"
    assert library.closed


def test_npcap_check_says_how_many_interfaces_and_whether_the_card_declares_monitor_mode():
    check = backends.NpcapBackend(lambda: FakeNpcap(FakeClock(), monitor=True)).check("192.168.1.2")

    assert check.usable and check.interfaces == 2 and check.monitor_mode is True


def test_npcap_not_installed_is_reported_and_never_installed():
    check = backends.NpcapBackend(lambda: None).check()

    assert not check.usable and not check.present and check.reason == "NO_CAPTURE_TOOL"


def test_npcap_restricted_to_administrators_is_a_permission_problem():
    library = FakeNpcap(FakeClock(), open_error="Error opening adapter: Access is denied. (5)")

    with pytest.raises(backends.CaptureFailed) as failed:
        backends.NpcapBackend(lambda: library).capture(session())
    assert failed.value.reason == "PERMISSION_DENIED"


def test_an_error_in_the_middle_of_an_npcap_capture_fails_and_still_closes_the_adapter():
    clock = FakeClock()
    library = FakeNpcap(clock, [samples.arp_request()] * 10, fail_at=3)

    with pytest.raises(backends.CaptureFailed) as failed:
        backends.NpcapBackend(lambda: library).capture(session(clock=clock))
    assert failed.value.reason == "CAPTURE_ERROR" and "desconectó" in failed.value.detail
    assert library.closed


def test_asking_to_stop_ends_the_capture_as_cancelled():
    clock = FakeClock()
    library = FakeNpcap(clock, [samples.arp_request()] * 50)
    s = session(clock=clock, stop=lambda: clock.now >= 1.0)

    backends.NpcapBackend(lambda: library).capture(s)

    assert s.stats.stop_reason == "CANCELLED" and s.stats.packets == 2  # leídos antes de notar el pedido


# ------------------------------------------------------------------------------------------------------ pktmon

class FakePktmon:
    """Responde como pktmon y escribe los archivos que pktmon escribiría (con paquetes sintéticos)."""

    def __init__(self, frames, start_fails=False, modern=True, stop_output=b"Lost events: 4\r\n", hang=None):
        self.frames, self.start_fails, self.modern, self.stop_output, self.hang = frames, start_fails, modern, \
            stop_output, hang
        self.calls = []

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        assert all(isinstance(a, str) for a in args)  # siempre argumentos separados, nunca una línea de consola
        verb = args[1]
        if self.hang == verb:
            raise subprocess.TimeoutExpired(args, timeout)
        if verb == "start":
            if self.start_fails or (not self.modern and "--capture" in args):
                return subprocess.CompletedProcess(args, 1, b"", b"Access is denied.")
            target = args[args.index("--file-name") + 1] if "--file-name" in args else args[args.index("-f") + 1]
            open(target, "wb").write(b"ETL")
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if verb == "stop":
            return subprocess.CompletedProcess(args, 0, self.stop_output, b"")
        if verb in ("etl2pcap", "pcapng"):
            if verb == "etl2pcap" and not self.modern:
                return subprocess.CompletedProcess(args, 1, b"", b"Unknown command")
            out = args[args.index("--out") + 1] if "--out" in args else args[args.index("-o") + 1]
            open(out, "wb").write(samples.pcapng(self.frames))
            return subprocess.CompletedProcess(args, 0, b"", b"")
        raise AssertionError(args)


def pktmon(runner, elevated=True):
    return backends.PktmonBackend(runner=runner, which=lambda name: r"C:\Windows\System32\PktMon.exe",
                                  elevated=lambda: elevated, windows=True)


def test_pktmon_captures_headers_only_of_the_network_cards_and_converts_the_file(tmp_path):
    runner = FakePktmon([(10.0, samples.https_out()), (10.5, samples.dns_query())])
    clock = FakeClock()
    with TempCapture(captures_dir(tmp_path)) as temp:
        s = session(temp=temp, clock=clock)
        run = pktmon(runner).capture(s)
        assert temp.file("captura.pcapng").exists()

    start = runner.calls[0]
    assert start[:3] == ["pktmon", "start", "--capture"]
    assert start[start.index("--comp") + 1] == "nics" and start[start.index("--pkt-size") + 1] == "128"
    assert [call[1] for call in runner.calls] == ["start", "stop", "etl2pcap"]
    assert s.stats.packets == 2 and run.dropped_by_tool == 4
    assert temp.removed  # el .etl y el .pcapng se borraron al terminar


def test_pktmon_on_windows_10_1809_uses_its_older_commands(tmp_path):
    runner = FakePktmon([(1.0, samples.arp_request())], modern=False)
    with TempCapture(captures_dir(tmp_path)) as temp:
        s = session(temp=temp)
        pktmon(runner).capture(s)

    verbs = [call[1] for call in runner.calls]
    assert verbs == ["start", "start", "stop", "etl2pcap", "pcapng"]
    assert runner.calls[1][2] == "--etw" and s.stats.packets == 1


def test_pktmon_without_administrator_is_not_usable_and_says_why():
    check = pktmon(FakePktmon([]), elevated=False).check()

    assert not check.usable and check.present and check.reason == "PERMISSION_DENIED"


def test_pktmon_only_exists_on_windows():
    check = backends.PktmonBackend(windows=False).check()

    assert check.reason == "UNSUPPORTED_OS" and not check.present


def test_pktmon_that_cannot_start_is_a_failure_with_its_reason(tmp_path):
    with TempCapture(captures_dir(tmp_path)) as temp, pytest.raises(backends.CaptureFailed) as failed:
        pktmon(FakePktmon([], start_fails=True)).capture(session(temp=temp))

    assert failed.value.reason == "PERMISSION_DENIED"


def test_pktmon_that_hangs_is_stopped_by_the_timeout(tmp_path):
    with TempCapture(captures_dir(tmp_path)) as temp, pytest.raises(backends.CaptureFailed) as failed:
        pktmon(FakePktmon([], hang="etl2pcap")).capture(session(temp=temp))

    assert failed.value.reason == "CAPTURE_ERROR" and "no respondió" in failed.value.detail


def test_pktmon_reading_stops_at_the_packet_limit(tmp_path):
    runner = FakePktmon([(1.0 + i / 10, samples.arp_request()) for i in range(20)], stop_output=b"")
    with TempCapture(captures_dir(tmp_path)) as temp:
        s = session(limits=Limits(5, 5, 10_000_000), temp=temp)
        run = pktmon(runner).capture(s)

    assert s.stats.packets == 5 and s.stats.stop_reason == "PACKET_LIMIT"
    assert run.dropped_by_tool is None  # pktmon no lo dijo: desconocido, no cero


def test_pktmon_lost_events_are_read_in_spanish_too():
    assert backends.LOST_EVENTS.search("Eventos perdidos: 12").group(1) == "12"


# ------------------------------------------------------------------------------------------------- elegir una

class Fixed:
    def __init__(self, code, check):
        self.code, self._check = code, check

    def check(self, own_ip=None):
        if isinstance(self._check, Exception):
            raise self._check
        return self._check


def test_the_first_usable_tool_is_chosen_in_order_of_preference():
    chosen, checks = backends.choose_backend([
        Fixed("NPCAP", backends.Check(False, False, "NO_CAPTURE_TOOL")),
        Fixed("PKTMON", backends.Check(True, True, interfaces=1)),
        Fixed("RAW_SOCKET", RuntimeError("no debería revisarse")),
    ], "192.168.1.2")

    assert chosen.code == "PKTMON" and list(checks) == ["NPCAP", "PKTMON"]


def test_a_broken_tool_does_not_prevent_checking_the_others():
    chosen, checks = backends.choose_all([Fixed("NPCAP", OSError("dll dañada")),
                                          Fixed("PKTMON", backends.Check(True, True, interfaces=1))], None)

    assert chosen.code == "PKTMON" and checks["NPCAP"].reason == "CAPTURE_ERROR"


@pytest.mark.parametrize("reasons, expected", [
    ([("NO_CAPTURE_TOOL", False), ("PERMISSION_DENIED", True)], "PERMISSION_DENIED"),
    ([("NO_CAPTURE_TOOL", False), ("NO_CAPTURE_TOOL", False)], "NO_CAPTURE_TOOL"),
    ([("UNSUPPORTED_OS", False)], "UNSUPPORTED_OS"),
    ([("NO_INTERFACE", True), ("NO_CAPTURE_TOOL", False)], "NO_INTERFACE"),
])
def test_without_a_tool_the_most_useful_reason_is_given(reasons, expected):
    checks = {f"T{i}": backends.Check(False, present, reason) for i, (reason, present) in enumerate(reasons)}

    assert backends.failure_without_tool(checks) == expected


# --------------------------------------------------------------------------------------------------- sockets

class FakeSocket:
    def __init__(self, packets):
        self.packets, self.closed = list(packets), False

    def settimeout(self, value):
        pass

    def recvfrom(self, size):
        if not self.packets:
            raise socket.timeout()
        return self.packets.pop(0)

    def close(self):
        self.closed = True


def test_the_linux_packet_socket_ignores_frames_meant_for_other_computers():
    sock = FakeSocket([(samples.https_in(), ("wlan0", 0x0800, 0)),
                       (samples.https_out(), ("wlan0", 0x0800, backends.PACKET_OTHERHOST)),
                       (samples.mdns(), ("wlan0", 0x0800, 2))])
    clock = FakeClock()
    backend = backends.PacketSocketBackend(opener=lambda ip: (sock, "wlan0"))

    def advancing():
        clock.now += 1
        return clock.now
    s = backends.Session(CaptureStats(Limits(4, 100, 10 ** 6), frozenset({"192.168.1.2"})), lambda: False,
                         clock=advancing, wall=lambda: 1000.0 + clock.now)
    run = backend.capture(s)

    assert run.interface_name == "wlan0" and s.stats.packets == 2 and sock.closed


def test_a_socket_without_permission_is_reported_as_such():
    def denied(ip):
        raise PermissionError("Operation not permitted")

    check = backends.PacketSocketBackend(opener=denied).check()
    assert check.reason == "PERMISSION_DENIED" and check.present
    with pytest.raises(backends.CaptureFailed) as failed:
        backends.PacketSocketBackend(opener=denied).capture(session())
    assert failed.value.reason == "PERMISSION_DENIED"


def test_the_default_interface_comes_from_the_route_table():
    table = ("Iface\tDestination\tGateway\tFlags\n"
             "docker0\t000011AC\t00000000\t0001\n"
             "wlan0\t00000000\t0101A8C0\t0003\n")

    assert backends.default_interface(table) == "wlan0"
    assert backends.default_interface("Iface\tDestination\n") is None


def can_capture_for_real() -> bool:
    if not hasattr(socket, "AF_PACKET") or os.geteuid() != 0:
        return False
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not can_capture_for_real(), reason="captura real: necesita Linux con root y AF_PACKET")
def test_a_real_capture_on_the_loopback_interface_counts_the_packets_sent():
    """Prueba de integración en este mismo computador: se envían 20 datagramas UDP a 127.0.0.1:5353... por la
    interfaz de bucle local y la captura real los cuenta como mDNS, sin guardar su contenido."""
    stats = CaptureStats(Limits(3, 1000, 10 ** 7), frozenset({"127.0.0.1"}))
    backend = backends.PacketSocketBackend(interface=lambda: "lo")
    s = backends.Session(stats, lambda: False, own_ip="127.0.0.1")

    def send():
        time.sleep(0.5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for _ in range(20):
                sender.sendto(b"password=secreto", ("127.0.0.1", 5353))
                time.sleep(0.01)
    thread = threading.Thread(target=send)
    thread.start()
    run = backend.capture(s)
    thread.join()

    assert run.interface_name == "lo"
    assert stats.protocols["MDNS"] >= 20
    result = stats.result(1, "PACKET_SOCKET", run.interface_name, "2.0.0", 3000, None)
    assert "secreto" not in repr(result) and "127.0.0.1" not in repr(result)
