"""
Filename: test_analysis.py
Description: Unit tests for analysis functions in packet_capture.
"""
from types import SimpleNamespace
import packet_capture.analysis as ana
from packet_capture.packet import DnsInfo


def make_packet(src, dst, src_port, dst_port, protocol='TCP', length=60, timestamp=0, flags=(), dns=None, transport: str | None = 'TCP'):
    """
    Builds a stand-in for a Packet, with the same attributes, without needing a capture file.

    The tests pass ports as ints (e.g. 80), but a real Packet gives them as strings (e.g. "80"). The analysis
    works with either, but keep it in mind if Packet ever converts ports to int.
    """
    return SimpleNamespace(src=src, dst=dst, src_port=src_port, dst_port=dst_port, protocol=protocol,
                           transport=transport, length=length, timestamp=timestamp, flags=list(flags), dns=dns)

# ---- General stats ----

# 4 packets between 3 hosts: 3 TCP and 1 UDP, 750 bytes in total.
# Every source port is the service port (80, 53, 443), as if each packet were a server's reply. In real
# traffic about half the packets come from the client's random port, which top_ports then counts
# instead of the service port; this data doesn't show that.
sample_packets = [
    make_packet('host1', 'host2', 80, 50000, protocol='TCP', length=100, timestamp=1),
    make_packet('host2', 'host1', 53, 50001, protocol='UDP', transport='UDP', length=200, timestamp=2),
    make_packet('host1', 'host2', 80, 50000, protocol='TCP', length=150, timestamp=3),
    make_packet('host3', 'host1', 443, 50002, protocol='TCP', length=300, timestamp=4),
]

# A complete TCP handshake (SYN, SYN-ACK, ACK) from host1:5000 to host2:80 then disconnects with FIN.
tcp_handshake_packets = [
    make_packet('host1', 'host2', 5000, 80, flags=['SYN']),
    make_packet('host2', 'host1', 80, 5000, flags=['SYN', 'ACK']),
    make_packet('host1', 'host2', 5000, 80, flags=['ACK']),
    make_packet('host1', 'host2', 5000, 80, flags=['FIN']),
    make_packet('host2', 'host1', 80, 5000, flags=['FIN', 'ACK']),
    make_packet('host1', 'host2', 5000, 80, flags=['ACK']),
]


def test_totals():
    total_packets, total_bytes = ana.totals(sample_packets)
    assert total_packets == 4
    assert total_bytes == 750

def test_protocol_counts():
    counts = ana.protocol_counts(sample_packets)
    assert counts == {'TCP': 3, 'UDP': 1}

def test_top_hosts():
    # Only the source is counted, so host2 counts once even though it's in 3 packets.
    # This is the current behavior, not necessarily the intended one.
    top = ana.top_hosts(sample_packets)
    assert top == [('host1', 2), ('host2', 1), ('host3', 1)]

def test_top_ports():
    top = ana.top_ports(sample_packets)
    assert top == [(80, 2), (53, 1), (443, 1)]

def test_conversations():
    convos = ana.conversations(sample_packets)
    assert convos == {('host1', 'host2'): 2, ('host2', 'host1'): 1, ('host3', 'host1'): 1}

def test_top_conversations():
    top = ana.top_conversations(sample_packets)
    assert top == [(('host1', 'host2'), 2), (('host2', 'host1'), 1), (('host3', 'host1'), 1)]

def test_traffic_over_time():
    traffic = ana.traffic_over_time(sample_packets)
    assert traffic == {1: 1, 2: 1, 3: 1, 4: 1}

# ---- TCP handshakes ----

def test_tcp_handshake_identifier():
    handshakes = ana.tcp_handshake_identifier(tcp_handshake_packets)
    assert handshakes == [('host1', 'host2')]

def test_tcp_handshake_needs_final_ack():
    handshakes = ana.tcp_handshake_identifier(tcp_handshake_packets[:2])
    assert handshakes == []

def test_tcp_handshake_ignores_ack_from_another_connection():
    # same two hosts, but the final ACK comes from a different client port
    packets = tcp_handshake_packets[:2] + [make_packet('host1', 'host2', 6000, 80, flags=['ACK'])]
    assert ana.tcp_handshake_identifier(packets) == []

def test_tcp_handshake_keeps_connections_apart():
    # two connections between the same hosts, with their packets interleaved
    packets = [
        make_packet('host1', 'host2', 5000, 80, flags=['SYN']),
        make_packet('host1', 'host2', 5001, 80, flags=['SYN']),
        make_packet('host2', 'host1', 80, 5000, flags=['SYN', 'ACK']),
        make_packet('host2', 'host1', 80, 5001, flags=['SYN', 'ACK']),
        make_packet('host1', 'host2', 5001, 80, flags=['ACK']),
        make_packet('host1', 'host2', 5000, 80, flags=['ACK']),
    ]
    assert ana.tcp_handshake_identifier(packets) == [('host1', 'host2'), ('host1', 'host2')]

def test_tcp_handshake_skips_non_tcp_packets():
    packets = [make_packet(None, None, None, None, protocol='ARP', transport=None)] + tcp_handshake_packets
    assert ana.tcp_handshake_identifier(packets) == [('host1', 'host2')]

# ---- Filtering ----

def test_filter_packets_no_filters_keeps_everything():
    assert ana.filter_packets(sample_packets) == sample_packets

def test_filter_packets_by_protocol():
    assert ana.filter_packets(sample_packets, protocols=['UDP']) == [sample_packets[1]]

def test_filter_packets_by_ip_matches_source_or_destination():
    # host3 is only ever a source; host2 is a source once and a destination twice
    assert ana.filter_packets(sample_packets, ips=['host3']) == [sample_packets[3]]
    assert ana.filter_packets(sample_packets, ips=['host2']) == sample_packets[:3]

def test_filter_packets_by_port_matches_source_or_destination():
    assert ana.filter_packets(sample_packets, ports=[443]) == [sample_packets[3]]
    assert ana.filter_packets(sample_packets, ports=[50000]) == [sample_packets[0], sample_packets[2]]

def test_filter_packets_matches_ports_given_as_strings():
    # pyshark gives ports as strings, so "80" and 80 should match the same packets
    assert ana.filter_packets(sample_packets, ports=['80']) == ana.filter_packets(sample_packets, ports=[80])

def test_filter_packets_values_in_one_filter_are_or():
    assert ana.filter_packets(sample_packets, ports=[53, 443]) == [sample_packets[1], sample_packets[3]]

def test_filter_packets_different_filters_are_and():
    assert ana.filter_packets(sample_packets, protocols=['TCP'], ips=['host3']) == [sample_packets[3]]
    assert ana.filter_packets(sample_packets, protocols=['UDP'], ips=['host3']) == []

def test_filter_packets_skips_packets_without_ports():
    arp = make_packet(None, None, None, None, protocol='ARP', transport=None)
    assert ana.filter_packets([arp] + sample_packets, ports=[80]) == [sample_packets[0], sample_packets[2]]

# ---- DNS ----

def dns_query(client, server, domain, query_type='A'):
    """Builds a stand-in DNS query packet from client to server, looking up domain."""
    return make_packet(client, server, 50000, 53, protocol='DNS', transport='UDP',
                       dns=DnsInfo(query=domain, query_type=query_type, is_response=False))

def dns_response(server, client, domain, rcode='NOERROR', answers=(), response_time: float | None = 0.01, query_type='A'):
    """Builds a stand-in DNS response packet from server to client, answering a lookup of domain."""
    return make_packet(server, client, 53, 50000, protocol='DNS', transport='UDP',
                       dns=DnsInfo(query=domain, query_type=query_type, is_response=True, rcode=rcode,
                                   answers=list(answers), response_time=response_time))

# Sample DNS traffic: two lookups of example.com (one AAAA), one of test.org, and one domain that doesn't exist
dns_packets = [
    dns_query('client1', 'dns1', 'example.com'),
    dns_response('dns1', 'client1', 'example.com', answers=['1.2.3.4'], response_time=0.02),
    dns_query('client1', 'dns1', 'example.com', query_type='AAAA'),
    dns_response('dns1', 'client1', 'example.com', answers=['2001:db8::1'], response_time=0.04, query_type='AAAA'),
    dns_query('client2', 'dns2', 'test.org'),
    dns_response('dns2', 'client2', 'test.org', answers=['5.6.7.8'], response_time=None),  # query wasn't captured
    dns_query('client2', 'dns1', 'nope.invalid'),
    dns_response('dns1', 'client2', 'nope.invalid', rcode='NXDOMAIN', response_time=0.03),
] + sample_packets   # non-DNS packets mixed in

def test_dns_queries_and_responses():
    # the first 8 packets alternate query, response, so queries are at even positions and responses at odd
    assert ana.dns_queries(dns_packets) == dns_packets[0:8:2]
    assert ana.dns_responses(dns_packets) == dns_packets[1:8:2]

def test_top_domains():
    assert ana.top_domains(dns_packets) == [('example.com', 2), ('test.org', 1), ('nope.invalid', 1)]

def test_top_domains_counts_queries_not_responses():
    assert ana.top_domains(ana.dns_responses(dns_packets)) == []

def test_dns_query_types():
    assert ana.dns_query_types(dns_packets) == {'A': 3, 'AAAA': 1}

def test_failed_dns_lookups():
    assert ana.failed_dns_lookups(dns_packets) == [(('nope.invalid', 'NXDOMAIN'), 1)]

def test_dns_servers():
    assert ana.dns_servers(dns_packets) == [('dns1', 3), ('dns2', 1)]

def test_dns_response_times_skips_unmatched_responses():
    assert ana.dns_response_times(dns_packets) == [0.02, 0.04, 0.03]

def test_dns_functions_without_dns_packets():
    assert ana.top_domains(sample_packets) == []
    assert ana.failed_dns_lookups(sample_packets) == []
    assert ana.dns_response_times(sample_packets) == []

# ---- TCP connections ----

def tcp_packet(src, dst, src_port, dst_port, flags, timestamp=0, length=60):
    """Builds a stand-in TCP packet with the given flags, e.g. ['SYN', 'ACK']."""
    return make_packet(src, dst, src_port, dst_port, flags=flags, timestamp=timestamp, length=length)

# A full connection from host1:5000 to host2:80: handshake, data both ways, then closed with FIN
full_connection = [
    tcp_packet('host1', 'host2', 5000, 80, ['SYN'], timestamp=1),
    tcp_packet('host2', 'host1', 80, 5000, ['SYN', 'ACK'], timestamp=2),
    tcp_packet('host1', 'host2', 5000, 80, ['ACK'], timestamp=3),
    tcp_packet('host1', 'host2', 5000, 80, ['PSH', 'ACK'], timestamp=4, length=200),
    tcp_packet('host2', 'host1', 80, 5000, ['PSH', 'ACK'], timestamp=5, length=1000),
    tcp_packet('host1', 'host2', 5000, 80, ['FIN', 'ACK'], timestamp=6),
    tcp_packet('host2', 'host1', 80, 5000, ['FIN', 'ACK'], timestamp=7),
]

def test_tcp_connection_summary():
    [connection] = ana.tcp_connections(full_connection)
    assert (connection.client, connection.client_port, connection.server, connection.server_port) == ('host1', 5000, 'host2', 80)
    assert connection.packets == 7
    assert connection.bytes_from_client == 60 + 60 + 200 + 60
    assert connection.bytes_from_server == 60 + 1000 + 60
    assert connection.bytes == connection.bytes_from_client + connection.bytes_from_server
    assert (connection.start, connection.end, connection.duration) == (1, 7, 6)
    assert connection.handshake is True
    assert connection.status == "closed"

def test_tcp_connection_reset():
    packets = full_connection[:4] + [tcp_packet('host2', 'host1', 80, 5000, ['RST'])]
    [connection] = ana.tcp_connections(packets)
    assert connection.status == "reset"

def test_tcp_connection_still_open():
    [connection] = ana.tcp_connections(full_connection[:5])
    assert connection.handshake is True
    assert connection.status == "open"

def test_tcp_connection_without_handshake():
    # SYN and SYN-ACK, but the client never sends the final ACK
    [connection] = ana.tcp_connections(full_connection[:2])
    assert connection.handshake is False

def test_tcp_connection_started_before_capture():
    # no SYN, and the first packet is from the server, so the lower port (80) is taken as the server
    [connection] = ana.tcp_connections(full_connection[4:])
    assert (connection.client, connection.server, connection.server_port) == ('host1', 'host2', 80)
    assert connection.handshake is False
    assert connection.bytes_from_server == 1000 + 60

def test_tcp_connection_port_reused():
    # the same client port used again for a new connection after the first one closed
    connections = ana.tcp_connections(full_connection + full_connection)
    assert len(connections) == 2
    assert all(connection.packets == 7 for connection in connections)

def test_tcp_connection_retransmitted_syn():
    # the client sends its SYN twice before the server answers: still one connection
    packets = full_connection[:1] + full_connection
    [connection] = ana.tcp_connections(packets)
    assert connection.packets == 8
    assert connection.handshake is True

def test_tcp_connections_kept_apart_and_skip_non_tcp():
    other = [tcp_packet('host1', 'host2', 6000, 443, ['SYN']), tcp_packet('host2', 'host1', 443, 6000, ['SYN', 'ACK'])]
    arp = make_packet(None, None, None, None, protocol='ARP', transport=None)
    connections = ana.tcp_connections(full_connection + other + [arp] + sample_packets[1:2])  # sample_packets[1] is UDP
    assert [(c.client_port, c.server_port) for c in connections] == [(5000, 80), (6000, 443)]

def test_top_server_ports():
    other = [tcp_packet('host3', 'host2', 7000, 80, ['SYN']), tcp_packet('host1', 'host2', 6000, 443, ['SYN'])]
    connections = ana.tcp_connections(full_connection + other)
    assert ana.top_server_ports(connections) == [(80, 2), (443, 1)]
