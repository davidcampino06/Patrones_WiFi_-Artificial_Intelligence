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
