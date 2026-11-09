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
