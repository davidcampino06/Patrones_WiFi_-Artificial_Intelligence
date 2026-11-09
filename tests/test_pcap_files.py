"""Lectura de archivos pcap y pcapng (los que deja pktmon), incluidos los dañados."""
import io

import pytest

from agent import pcap_files
from tests import capture_samples as samples


def frames_of(raw: bytes):
    summary = pcap_files.FileSummary()
    return list(pcap_files.read_frames(io.BytesIO(raw), summary)), summary


@pytest.mark.parametrize("order", ["<", ">"])
def test_a_pcap_file_in_either_byte_order_gives_its_packets_with_their_time(order):
    frames, summary = frames_of(samples.pcap([(10.5, samples.arp_request()), (11.25, samples.dns_query())],
                                             order=order))

    assert [round(f.timestamp, 2) for f in frames] == [10.5, 11.25]
    assert frames[0].link_type == 1 and frames[0].data == samples.arp_request()
    assert not summary.damaged and summary.dropped_by_tool is None


def test_nanosecond_pcap_keeps_the_fraction():
    frames, _ = frames_of(samples.pcap([(3.000000250, samples.mdns())], nanoseconds=True))

    assert frames[0].timestamp == pytest.approx(3.00000025)


def test_a_pcapng_file_uses_the_time_resolution_of_its_interface_and_the_drops_the_tool_reported():
    frames, summary = frames_of(samples.pcapng([(100.0, samples.https_out()), (100.75, samples.https_in())],
                                               tsresol=9, dropped=17))

    assert [f.timestamp for f in frames] == pytest.approx([100.0, 100.75])
    assert summary.dropped_by_tool == 17
    assert not summary.damaged


def test_a_big_endian_pcapng_and_a_simple_packet_block_are_read():
    frames, _ = frames_of(samples.pcapng([(1.0, samples.arp_request()), (2.0, samples.dns_query())], order=">",
                                         simple_first=True))

    assert len(frames) == 2
    assert frames[0].data == samples.arp_request()
    assert frames[1].timestamp == pytest.approx(2.0)


def test_a_truncated_file_stops_quietly_and_says_it_was_damaged():
    raw = samples.pcapng([(1.0, samples.arp_request()), (2.0, samples.dns_query())])
    frames, summary = frames_of(raw[:-10])

    assert len(frames) == 1
    assert summary.damaged


def test_a_truncated_pcap_record_is_not_invented():
    raw = samples.pcap([(1.0, samples.arp_request())])
    frames, summary = frames_of(raw[:-5])

    assert frames == [] and summary.damaged


@pytest.mark.parametrize("raw", [b"", b"PK\x03\x04no es una captura"])
def test_something_that_is_not_a_capture_is_an_error(raw):
    with pytest.raises(pcap_files.CaptureFileError):
        frames_of(raw)


def test_a_block_that_claims_to_be_huge_is_treated_as_damage_not_read():
    raw = samples.pcapng([(1.0, samples.arp_request())])
    broken = raw + (6).to_bytes(4, "little") + (1 << 30).to_bytes(4, "little")
    frames, summary = frames_of(broken)

    assert len(frames) == 1 and summary.damaged
