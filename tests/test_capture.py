"""
Filename: test_capture.py
Description: Tests reading a real capture file into Packet objects, using known frames from
             TheUltimateCapture.pcapng.

capture[i] is frame i + 1: the list starts at 0, but Wireshark numbers frames from 1.
"""

from pathlib import Path
import pytest
# imported from where each is defined; scapy.all builds its names at runtime, so Pylance can't see them
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
import packet_capture.analysis as ana
from packet_capture.capture import capture_file
from packet_capture.packet import Packet

CAPTURE = str(Path(__file__).parent / "captures" / "TheUltimateCapture.pcapng")

# A fixture is setup code pytest runs for any test that asks for it by name.
# Code after `yield` is cleanup, and it runs even if the test fails.
# scope="module" opens the capture once for all the tests in this file, since pyshark
# keeps the packets it has read and the file is large.
@pytest.fixture(scope="module")
def capture():
    cap = capture_file(CAPTURE)
    yield cap
    cap.close()

def test_non_ip_packet_fields(capture):
    # frame 1 is a RARP request, which has no IP or port information.
    # Wireshark handles RARP with its ARP dissector, so pyshark labels it ARP.
    pkt = Packet(capture[0])
    assert pkt.protocol == "ARP"
    assert pkt.src is None
    assert pkt.dst is None
    assert pkt.src_port is None
    assert pkt.dst_port is None
    assert pkt.flags == []
    assert pkt.transport is None
    assert pkt.length == 60

def test_dhcp_packet_fields(capture):
    pkt = Packet(capture[1595])   # frame 1596
    assert pkt.protocol == "DHCP"
    assert pkt.src == "0.0.0.0"
    assert pkt.dst == "255.255.255.255"
    assert pkt.src_port == "68"   # pyshark gives ports as strings
    assert pkt.dst_port == "67"
    assert pkt.flags == []        # UDP, so no TCP flags
    assert pkt.transport == "UDP"
    assert pkt.length == 342

def test_tcp_syn_packet_flags(capture):
    pkt = Packet(capture[960])    # frame 961, a TCP SYN
    assert pkt.protocol == "TCP"
    assert pkt.transport == "TCP"
    assert pkt.flags == ["SYN"]

def test_ipv6_packet_addresses(capture):
    pkt = Packet(capture[5207])   # frame 5208, a TCP SYN over IPv6
    assert pkt.src == "2003:51:6012:110::b15:22"
    assert pkt.dst == "2003:51:6012:121::2"
    assert pkt.transport == "TCP"
    assert pkt.dst_port == "22"

def test_non_dns_packet_has_no_dns(capture):
    assert Packet(capture[0]).dns is None

def test_dns_query_fields(capture):
    dns = Packet(capture[1624]).dns   # frame 1625
    # Fails clearly if the frame has no DNS, and tells Pylance dns isn't None for the lines below.
    # The other DNS tests do the same.
    assert dns is not None
    assert dns.query == "heise.de"
    assert dns.query_type == "A"
    assert dns.is_response is False
    assert dns.rcode is None
    assert dns.answers == []

def test_dns_response_fields(capture):
    dns = Packet(capture[1625]).dns   # frame 1626, the answer to frame 1625
    assert dns is not None
    assert dns.query == "heise.de"
    assert dns.is_response is True
    assert dns.rcode == "NOERROR"
    assert dns.answers == ["193.99.144.80"]
    # approx compares floats with a small tolerance, since 0.010356 may not be stored exactly
    assert dns.response_time == pytest.approx(0.010356)

def test_dns_failed_lookup(capture):
    dns = Packet(capture[2100]).dns   # frame 2101, reverse lookup of an address with no name
    assert dns is not None
    assert dns.query == "239.108.154.80.in-addr.arpa"
    assert dns.query_type == "PTR"
    assert dns.rcode == "NXDOMAIN"
    assert dns.answers == []

def test_dns_response_with_several_answers(capture):
    dns = Packet(capture[2104]).dns   # frame 2105, with both IPv4 (A) and IPv6 (AAAA) answers
    assert dns is not None
    assert dns.answers == ["80.154.108.230", "213.61.29.182", "2003:51:6012:110::a07:53"]

# Checks that an error is raised, instead of letting it crash the test
def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        capture_file("does_not_exist.pcapng")

@pytest.mark.skip(reason="needs a real interface; TODO: mock it")
def test_live_network_capture():
    ...

@pytest.mark.skip(reason="TODO")
def test_remote_capture():
    ...

# ---- Generated traffic (Scapy) ----
# Packets built with Scapy, so the expected values are worked out from what was generated,
# not looked up in a capture.

def write_capture(tmp_path, packets):
    """Writes Scapy packets to a .pcap in tmp_path and reads them back as Packet objects."""
    path = str(tmp_path / "generated.pcap")
    wrpcap(path, packets)
    cap = capture_file(path)
    result = [Packet(raw_packet) for raw_packet in cap]
    cap.close()
    return result

def test_generated_tcp_syn(tmp_path):
    syn = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=50000, dport=80, flags="S")
    [pkt] = write_capture(tmp_path, [syn])
    assert (pkt.src, pkt.dst) == ("10.0.0.2", "10.0.0.1")
    assert (pkt.src_port, pkt.dst_port) == ("50000", "80")
    assert pkt.transport == "TCP"
    assert pkt.flags == ["SYN"]
    assert pkt.length == 54   # Ethernet (14) + IP (20) + TCP (20) headers, no data

def test_generated_packet_with_two_flags(tmp_path):
    syn_ack = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=50000, flags="SA")
    [pkt] = write_capture(tmp_path, [syn_ack])
    assert pkt.flags == ["SYN", "ACK"]   # Scapy's "SA"; tshark flags as 0x012 (SYN 0x02, ACK 0x10)

def test_generated_tcp_handshake(tmp_path):
    client, server = "10.0.0.2", "10.0.0.1"
    packets = write_capture(tmp_path, [
        Ether() / IP(src=client, dst=server) / TCP(sport=50000, dport=80, flags="S"),
        Ether() / IP(src=server, dst=client) / TCP(sport=80, dport=50000, flags="SA"),
        Ether() / IP(src=client, dst=server) / TCP(sport=50000, dport=80, flags="A"),
    ])
    [connection] = ana.tcp_connections(packets)
    assert (connection.client, connection.client_port) == (client, "50000")
    assert (connection.server, connection.server_port) == (server, "80")
    assert connection.packets == 3
    assert connection.handshake is True
    assert connection.status == "open"   # not closed yet
    assert ana.tcp_handshake_identifier(packets) == [(client, server)]

def test_generated_tcp_graceful_close(tmp_path):
    client, server = "10.0.0.2", "10.0.0.1"
    to_server = Ether() / IP(src=client, dst=server)
    to_client = Ether() / IP(src=server, dst=client)
    generated = [
        to_server / TCP(sport=50000, dport=80, flags="S"),                     # handshake
        to_client / TCP(sport=80, dport=50000, flags="SA"),
        to_server / TCP(sport=50000, dport=80, flags="A"),
        to_server / TCP(sport=50000, dport=80, flags="PA") / Raw(b"x" * 100),  # 100 bytes of data up
        to_client / TCP(sport=80, dport=50000, flags="PA") / Raw(b"y" * 500),  # 500 bytes of data down
        to_server / TCP(sport=50000, dport=80, flags="FA"),                    # client closes
        to_client / TCP(sport=80, dport=50000, flags="FA"),                    # server closes
        to_server / TCP(sport=50000, dport=80, flags="A"),                     # client acknowledges
    ]
    # one packet every 0.1 seconds, so the connection lasts 0.7 seconds
    for i, packet in enumerate(generated):
        packet.time = 1_700_000_000 + i * 0.1
    [connection] = ana.tcp_connections(write_capture(tmp_path, generated))
    assert connection.packets == 8
    # paket times 54 bytes of headers plus data length of raw bytes
    assert connection.bytes_from_client == 5 * 54 + 100
    assert connection.bytes_from_server == 3 * 54 + 500
    assert connection.duration.total_seconds() == pytest.approx(0.7)
    assert connection.handshake is True
    assert connection.status == "closed"

def test_generated_tcp_refused(tmp_path):
    """TCP connection refused because server is not listening on port 8080, but on 80"""
    client, server = "10.0.0.2", "10.0.0.1"
    packets = write_capture(tmp_path, [
        Ether() / IP(src=client, dst=server) / TCP(sport=50001, dport=8080, flags="S"),
        Ether() / IP(src=server, dst=client) / TCP(sport=8080, dport=50001, flags="RA"),
    ])
    assert packets[1].flags == ["RST", "ACK"]
    [connection] = ana.tcp_connections(packets)
    assert (connection.client, connection.server_port) == (client, "8080")
    assert connection.packets == 2
    assert connection.handshake is False   # the SYN-ACK never came
    assert connection.status == "reset"

def test_generated_tcp_started_before_capture(tmp_path):
    """TCP connection where capture starts after the handshake"""
    client, server = "10.0.0.2", "10.0.0.1"
    packets = write_capture(tmp_path, [
        # no handshake: the capture starts partway through, with the server sending first
        Ether() / IP(src=server, dst=client) / TCP(sport=22, dport=50002, flags="PA") / Raw(b"z" * 50),
        Ether() / IP(src=client, dst=server) / TCP(sport=50002, dport=22, flags="A"),
    ])
    [connection] = ana.tcp_connections(packets)
    # without a SYN, the side with the lower port (22) is taken as the server
    assert (connection.client, connection.client_port) == (client, "50002")
    assert (connection.server, connection.server_port) == (server, "22")
    assert connection.bytes_from_server == 54 + 50
    assert connection.bytes_from_client == 54
    assert connection.handshake is False   # it happened before the capture started
    assert connection.status == "open"

def test_generated_tcp_port_reused(tmp_path):
    client, server = "10.0.0.2", "10.0.0.1"
    to_server = Ether() / IP(src=client, dst=server)
    to_client = Ether() / IP(src=server, dst=client)

    def short_connection():
        """A handshake and close from client:50000 to server:80, no data."""
        return [
            to_server / TCP(sport=50000, dport=80, flags="S"),
            to_client / TCP(sport=80, dport=50000, flags="SA"),
            to_server / TCP(sport=50000, dport=80, flags="A"),
            to_server / TCP(sport=50000, dport=80, flags="FA"),
            to_client / TCP(sport=80, dport=50000, flags="FA"),
            to_server / TCP(sport=50000, dport=80, flags="A"),
        ]

    # the same client port used twice, one connection after the other
    generated = short_connection()
    generated += short_connection()
    for i, packet in enumerate(generated):
        packet.time = 1_700_000_000 + i * 0.1
    first, second = ana.tcp_connections(write_capture(tmp_path, generated))

    # the second SYN comes after the first connection closed, so it starts a new connection
    assert first.client_port == second.client_port == "50000"
    assert first.packets == second.packets == 6
    assert first.handshake and second.handshake
    assert first.status == second.status == "closed"
    assert second.start > first.end


def test_generated_tcp_retransmitted_syn(tmp_path):
    client, server = "10.0.0.2", "10.0.0.1"
    to_server = Ether() / IP(src=client, dst=server)
    to_client = Ether() / IP(src=server, dst=client)
    generated = [
        to_server / TCP(sport=50000, dport=80, flags="S"),    # first try, no answer
        to_server / TCP(sport=50000, dport=80, flags="S"),    # the client tries again
        to_client / TCP(sport=80, dport=50000, flags="SA"),
        to_server / TCP(sport=50000, dport=80, flags="A"),
    ]
    # the retry comes 1 second after the first SYN, then the rest follow quickly
    for packet, seconds in zip(generated, [0.0, 1.0, 1.1, 1.2]):
        packet.time = 1_700_000_000 + seconds
    # the handshake hadn't finished when the second SYN came, so it's the same connection
    [connection] = ana.tcp_connections(write_capture(tmp_path, generated))
    assert connection.packets == 4
    assert connection.handshake is True
    assert connection.status == "open"
    assert connection.duration.total_seconds() == pytest.approx(1.2)

def test_generated_dns_lookup(tmp_path):
    """Generates DNS query and response"""
    client, resolver = "10.0.0.2", "10.0.0.53"
    question = DNSQR(qname="example.com", qtype="A")
    query = Ether() / IP(src=client, dst=resolver) / UDP(sport=40000, dport=53) / DNS(id=1, rd=1, qd=question)
    response = (Ether() / IP(src=resolver, dst=client) / UDP(sport=53, dport=40000)
                / DNS(id=1, qr=1, qd=question, an=[DNSRR(rrname="example.com", type="A", rdata="192.0.2.10")]))
    query.time, response.time = 1_700_000_000, 1_700_000_000.025   # the response comes 25 ms after the query
    packets = write_capture(tmp_path, [query, response])

    assert packets[0].dns is not None and packets[1].dns is not None
    asked, answered = packets[0].dns, packets[1].dns
    assert (asked.query, asked.query_type, asked.is_response) == ("example.com", "A", False)
    assert (answered.query, answered.is_response, answered.rcode) == ("example.com", True, "NOERROR")
    assert answered.answers == ["192.0.2.10"]
    assert answered.response_time == pytest.approx(0.025)

def test_generated_dns_nxdomain(tmp_path):
    """Generates DNS query and NXDOMAIN response (no domain)"""
    client, resolver = "10.0.0.2", "10.0.0.53"
    question = DNSQR(qname="nope.invalid", qtype="A")   # .invalid names are guaranteed not to exist
    query = Ether() / IP(src=client, dst=resolver) / UDP(sport=40001, dport=53) / DNS(id=2, rd=1, qd=question)
    # rcode 3 is NXDOMAIN: no such domain, so there are no answers
    response = Ether() / IP(src=resolver, dst=client) / UDP(sport=53, dport=40001) / DNS(id=2, qr=1, rcode=3, qd=question)
    packets = write_capture(tmp_path, [query, response])

    answered = packets[1].dns
    assert answered is not None
    assert (answered.query, answered.rcode) == ("nope.invalid", "NXDOMAIN")
    assert answered.answers == []
    assert ana.failed_dns_lookups(packets) == [(("nope.invalid", "NXDOMAIN"), 1)]
