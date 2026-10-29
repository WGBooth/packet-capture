"""
Filename: test_capture.py
Description: Tests reading a real capture file into Packet objects, using known frames from
             TheUltimateCapture.pcapng.

capture[i] is frame i + 1: the list starts at 0, but Wireshark numbers frames from 1.
"""

from pathlib import Path
import pytest
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