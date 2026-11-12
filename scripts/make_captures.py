"""
Filename: make_captures.py
Description: Generates synthetic traffic (Scapy) to .pcap files in tests/captures/generated/. View in Wireshark
and in the terminal for comparison purposes.
Usage: python(3) scripts/make_captures.py
"""
from pathlib import Path

# imported from the modules that define them, not scapy.all, so editors can find the names
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

OUTPUT = Path(__file__).parent.parent / "tests" / "captures" / "generated"
START = 1_700_000_000   # timestamp of the first packet in each capture

# ---- Scenarios ----
# Each returns its packets, with its prediction in the docstring.

def graceful_tcp_close():
    """
    A TCP connection from 10.0.0.2:50000 to 10.0.0.1:80 that opens, sends data both ways, and closes.

    Wireshark:
        - 8 packets, 0.1 s apart: SYN, SYN-ACK, ACK, data up (Len=100), data down (Len=500),
          FIN-ACK, FIN-ACK, ACK
        - Relative sequence numbers: the client's Seq goes 0, 1, 101, 102 (the SYN and FIN each count as 1)
        - Statistics > Conversations > TCP: 1 conversation, 8 packets, 1032 bytes, duration 0.7 s;
          client -> server 370 bytes (5 x 54 + 100), server -> client 662 bytes (3 x 54 + 500)
        - Analyze > Expert Information: no warnings or errors
    App (TCP tab): 1 connection, handshake True, status "closed"
    """
    client, server = "10.0.0.2", "10.0.0.1"
    to_server = Ether() / IP(src=client, dst=server)
    to_client = Ether() / IP(src=server, dst=client)
    # each side's starting sequence number; Wireshark shows sequence numbers relative to these
    c, s = 1000, 5000
    packets = [
        to_server / TCP(sport=50000, dport=80, flags="S", seq=c),                            # handshake
        to_client / TCP(sport=80, dport=50000, flags="SA", seq=s, ack=c + 1),
        to_server / TCP(sport=50000, dport=80, flags="A", seq=c + 1, ack=s + 1),
        to_server / TCP(sport=50000, dport=80, flags="PA", seq=c + 1, ack=s + 1) / Raw(b"x" * 100),  # data up
        to_client / TCP(sport=80, dport=50000, flags="PA", seq=s + 1, ack=c + 101) / Raw(b"y" * 500),  # data down
        to_server / TCP(sport=50000, dport=80, flags="FA", seq=c + 101, ack=s + 501),        # client closes
        to_client / TCP(sport=80, dport=50000, flags="FA", seq=s + 501, ack=c + 102),        # server closes
        to_server / TCP(sport=50000, dport=80, flags="A", seq=c + 102, ack=s + 502),         # client acknowledges
    ]
    # one packet every 0.1 seconds
    for i, packet in enumerate(packets):
        packet.time = START + i * 0.1
    return packets

def dns_request():
    """
    A DNS request from 10.0.0.2 to 10.0.0.1 for the domain "example.com".

    Wireshark:
        - 1 packet, DNS query
        - Analyze > Expert Information: no warnings or errors
    App (DNS tab): 1 query, top domain "example.com"
    """
    client, server = "10.0.0.2", "10.0.0.1"
    packet = Ether() / IP(src=client, dst=server) / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
    packet.time = START
    return [packet]

def arp_request():
    """
    An ARP request from 10.0.0.2 asking for the MAC address of 10.0.0.1.

    Wireshark:
        - 1 packet, ARP request
        - Analyze > Expert Information: no warnings or errors
    App: N/A (not TCP)
    """
    sender, target = "10.0.0.2", "10.0.0.1"
    packet = Ether() / ARP(op=1, hwsrc="00:00:00:00:00:02", psrc=sender, hwdst="00:00:00:00:00:01", pdst=target)
    packet.time = START
    return [packet]

SCENARIOS = [graceful_tcp_close, dns_request, arp_request]

def main():
    """Writes each scenario to OUTPUT/<name>.pcap and prints where it went and what to expect."""
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for scenario in SCENARIOS:
        path = OUTPUT / f"{scenario.__name__}.pcap"
        wrpcap(str(path), scenario())
        print(path)
        print(scenario.__doc__)

if __name__ == "__main__":
    main()
