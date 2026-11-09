"""Contract of POST /api/v1/traffic/analyze: the statistical summary of one technical capture, never a packet, an
address or a payload. connectionLossPct (the packet loss of the latest connection test of the network) travels apart
from droppedByTool (what the capture tool could not keep): they are different measurements and are never mixed."""
from pydantic import Field

from app.schemas import InputModel

PROTOCOL = (r"^(TCP|UDP|ICMP|ICMPV6|ARP|IGMP|DNS|MDNS|DHCP|SSDP|NETBIOS|LLMNR|HTTP|HTTPS|QUIC|NTP|IPV6_OTHER"
            r"|IPV4_OTHER|OTHER)$")


class ProtocolCount(InputModel):
    protocol: str = Field(pattern=PROTOCOL)
    packets: int = Field(ge=1, le=100_000)
    bytes: int = Field(ge=0, le=104_857_600)


class PortCount(InputModel):
    transport: str = Field(pattern=r"^(TCP|UDP)$")
    port: int = Field(ge=0, le=65535)
    packets: int = Field(ge=1, le=100_000)
    bytes: int = Field(ge=0, le=104_857_600)


class IntervalCount(InputModel):
    second: int = Field(ge=0, le=360)
    packets: int = Field(ge=1, le=100_000)
    bytes: int = Field(ge=0, le=104_857_600)


class TrafficRequest(InputModel):
    duration_seconds: float = Field(gt=0, le=400)
    packets: int = Field(ge=0, le=100_000)
    bytes: int = Field(ge=0, le=104_857_600)
    dropped_by_tool: int | None = Field(default=None, ge=0, le=100_000_000)
    malformed: int | None = Field(default=None, ge=0, le=100_000)
    inbound_bytes: int | None = Field(default=None, ge=0)
    outbound_bytes: int | None = Field(default=None, ge=0)
    broadcast: int | None = Field(default=None, ge=0, le=100_000)
    multicast: int | None = Field(default=None, ge=0, le=100_000)
    local_hosts: int | None = Field(default=None, ge=0, le=32_767)
    remote_hosts: int | None = Field(default=None, ge=0, le=100_000)
    stop_reason: str | None = Field(default=None, pattern=r"^(DURATION|PACKET_LIMIT|BYTE_LIMIT|CANCELLED)$")
    connection_loss_pct: float | None = Field(default=None, ge=0, le=100)
    protocols: list[ProtocolCount] = Field(default_factory=list, max_length=19)
    ports: list[PortCount] = Field(default_factory=list, max_length=20)
    intervals: list[IntervalCount] = Field(default_factory=list, max_length=361)
