"""Nombres que el propio router conoce, preguntados a su DNS sin clave; y lo que todavía no existe (bloquear)."""
import socket
import struct
import threading

import pytest

from agent import router_sources as routers


def answer(query: bytes, name: str = None, rcode: int = 0, compress: bool = True) -> bytes:
    """La respuesta que daría un router con dnsmasq."""
    query_id = struct.unpack("!H", query[:2])[0]
    question = query[12:]
    header = struct.pack("!HHHHHH", query_id, 0x8180 | rcode, 1, 1 if name else 0, 0, 0)
    if not name:
        return header + question
    owner = b"\xc0\x0c" if compress else question[:-4]
    rdata = routers.encode_name(name)
    return header + question + owner + struct.pack("!HHIH", 12, 1, 60, len(rdata)) + rdata


def test_the_question_is_a_standard_reverse_lookup():
    query = routers.ptr_query("192.168.1.23", 0x1234)

    assert query[:2] == b"\x12\x34"
    assert b"\x0223\x011\x03168\x03192\x07in-addr\x04arpa\x00" in query
    assert query.endswith(struct.pack("!HH", 12, 1))


@pytest.mark.parametrize("compress", [True, False])
def test_the_name_in_the_answer_is_read_with_or_without_compression(compress):
    query = routers.ptr_query("192.168.1.23", 77)

    assert routers.parse_ptr_answer(answer(query, "Portatil-de-Ana.lan", compress=compress)) == \
        (77, "Portatil-de-Ana.lan")


def test_a_router_that_does_not_know_the_address_gives_no_name():
    query = routers.ptr_query("192.168.1.99", 5)

    assert routers.parse_ptr_answer(answer(query, rcode=3)) == (5, None)  # NXDOMAIN
    assert routers.parse_ptr_answer(answer(query)) == (5, None)


@pytest.mark.parametrize("raw", [b"\x00\x01", b"\x00\x05\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\xc0\x0c"])
def test_a_broken_answer_is_rejected_instead_of_read_beyond_its_end(raw):
    with pytest.raises(ValueError):
        routers.parse_ptr_answer(raw)


def test_a_pointer_loop_cannot_hang_the_agent():
    looping = b"\x00" * 12 + b"\xc0\x0c"
    with pytest.raises(ValueError):
        routers.read_name(looping, 12)


class FakeRouterDns:
    """Un 'router' de verdad en 127.0.0.1 que responde PTR de su tabla de DHCP."""

    def __init__(self, table):
        self.table = table
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        self.sock.settimeout(3)
        try:
            while True:
                query, sender = self.sock.recvfrom(512)
                labels, offset = [], 12
                while query[offset]:
                    labels.append(query[offset + 1:offset + 1 + query[offset]].decode())
                    offset += 1 + query[offset]
                ip = ".".join(reversed(labels[:4]))
                self.sock.sendto(answer(query, self.table.get(ip), rcode=0 if ip in self.table else 3), sender)
        except OSError:
            return

    def close(self):
        self.sock.close()


def test_the_names_the_router_knows_are_asked_all_at_once_and_unknown_ones_are_left_out():
    router = FakeRouterDns({"192.168.1.23": "Portatil-de-Ana.lan", "192.168.1.40": "Galaxy-A54"})
    try:
        source = routers.GatewayDnsSource("127.0.0.1", timeout=1.0, port=router.port)
        found = source.names(["192.168.1.23", "192.168.1.40", "192.168.1.77"])
    finally:
        router.close()

    assert found == {"192.168.1.23": "Portatil-de-Ana.lan", "192.168.1.40": "Galaxy-A54"}


def test_answers_that_do_not_come_from_the_router_are_ignored():
    impostor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    impostor.bind(("127.0.0.1", 0))
    try:
        source = routers.GatewayDnsSource("127.0.0.2", timeout=0.5, port=impostor.getsockname()[1])
        assert source.names(["192.168.1.23"]) == {}
    finally:
        impostor.close()


def test_blocking_or_listing_clients_does_not_exist_yet_and_says_so():
    source = routers.source_for("192.168.1.1", "Huawei", "HG8145V5")

    with pytest.raises(routers.NotSupported):
        source.block("cualquiera")
    with pytest.raises(routers.NotSupported):
        source.clients()
    assert routers.SUPPORTED_OPERATIONS == {"READ_NAMES": True, "LIST_CLIENTS": False, "BLOCK_DEVICE": False,
                                            "CHANGE_PASSWORD": False}
    assert routers.source_for(None) is None
