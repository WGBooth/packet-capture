"""
Filename: analysis.py
Description: Analysis functions for packet capture data.
"""
from dataclasses import dataclass
from typing import Any

# ---- General stats ----

def totals(packets: list):
    """
    Counts the number of packets and total of bytes captured.

    Args:
        packets (list): List of Packet objects.

    Returns:
        tuple: A tuple containing the total number of packets and the total number of bytes.
    """
    total_packets = len(packets)
    total_bytes = sum(packet.length for packet in packets)
    return (total_packets, total_bytes)

def protocol_counts(packets):
    """
    Counts the number of packets for each protocol. A packet's protocol is its highest layer,
    so HTTPS traffic counts as TLS, not TCP.

    Args:
        packets (list): List of Packet objects.

    Returns:
        dict: A dictionary with protocols as keys and their respective packet counts as values.
    """
    counts = {}
    for packet in packets:
        proto = packet.protocol
        if proto in counts:
            counts[proto] += 1
        else:
            counts[proto] = 1
    return counts

def top_hosts(packets, n=5):
    """
    Finds the top n hosts by the number of packets.

    Args:
        packets (list): List of Packet objects. A packet's host is its source IP; packets without IP (e.g., ARP) are skipped.
        n (int): Number of top hosts to return. Default is 5.

    Returns:
        list: A list of tuples containing the host and its packet count, sorted by count in descending order.
    """
    counts = {}
    for packet in packets:
        host = packet.src or packet.dst
        if host is None:
            continue
        if host in counts:
            counts[host] += 1
        else:
            counts[host] = 1
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_counts[:n]

def top_ports(packets, n=5):
    """
    Finds the top n ports by the number of packets.

    Args:
        packets (list): List of Packet objects. A packet's port is its source port; packets without ports (e.g., ARP, ICMP) are skipped.
        n (int): Number of top ports to return. Default is 5.

    Returns:
        list: A list of tuples containing the port and its packet count, sorted by count in descending order.
    """
    counts = {}
    for packet in packets:
        # the source port (src_port and dst_port are either both set or both None)
        port = packet.src_port or packet.dst_port
        if port is None:
            continue
        if port in counts:
            counts[port] += 1
        else:
            counts[port] = 1
    # descending order by packet count
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_counts[:n]

def conversations(packets):
    """
    Finds all conversations between hosts. Each direction is counted separately, so A -> B and
    B -> A are two entries. Packets without IP are counted under (None, None).

    Args:
        packets (list): List of Packet objects.

    Returns:
        dict: A dictionary with tuples of (src, dst) as keys and their respective packet counts as values.
    """
    counts = {}
    for packet in packets:
        convo = (packet.src, packet.dst)
        if convo in counts:
            counts[convo] += 1
        else:
            counts[convo] = 1
    return counts

def top_conversations(packets, n=5):
    """
    Finds the top n conversations by the number of packets.

    Args:
        packets (list): List of Packet objects.
        n (int): Number of top conversations to return. Default is 5.

    Returns:
        list: A list of tuples containing the conversation (src, dst) and its packet count, sorted by count in descending order.
    """
    counts = conversations(packets)
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_counts[:n]

def traffic_over_time(packets):
    """
    Counts packets over time.

    Args:
        packets (list): List of Packet objects.

    Returns:
        dict: A dictionary with timestamps as keys and the number of packets at each exact timestamp as values.
            Nearly every packet has its own timestamp, so the app groups these into intervals for the chart.
    """
    counts = {}
    for packet in packets:
        timestamp = packet.timestamp
        if timestamp in counts:
            counts[timestamp] += 1
        else:
            counts[timestamp] = 1
    return counts

# ---- Filtering ----

def filter_packets(packets, protocols=None, ips=None, ports=None):
    """
    Keeps only the packets that match the filters. Each filter matches any of its values,
    and a packet has to match every filter that's given. An empty or None filter isn't applied.

    Args:
        packets (list): List of Packet objects.
        protocols (list): Keep packets whose protocol is one of these. This is the highest layer, so "TCP"
            doesn't include TLS, HTTP, or SSH packets.
        ips (list): Keep packets whose source or destination IP is one of these.
        ports (list): Keep packets whose source or destination port is one of these.

    Returns:
        list: The matching Packet objects, in their original order.
    """
    protocols = set(protocols or [])
    ips = set(ips or [])
    # compared as strings, since pyshark gives ports as strings
    ports = {str(port) for port in ports or []}

    filtered = []
    for packet in packets:
        if protocols and packet.protocol not in protocols:
            continue
        if ips and packet.src not in ips and packet.dst not in ips:
            continue
        if ports and str(packet.src_port) not in ports and str(packet.dst_port) not in ports:
            continue
        filtered.append(packet)
    return filtered

# ---- DNS ----

def dns_queries(packets):
    """
    Finds the DNS queries (questions asked, not the answers).

    Args:
        packets (list): List of Packet objects.

    Returns:
        list: The Packet objects that are DNS queries.
    """
    return [packet for packet in packets if packet.dns and not packet.dns.is_response]

def dns_responses(packets):
    """
    Finds the DNS responses (answers from a DNS server).

    Args:
        packets (list): List of Packet objects.

    Returns:
        list: The Packet objects that are DNS responses.
    """
    return [packet for packet in packets if packet.dns and packet.dns.is_response]

def top_domains(packets, n=10):
    """
    Finds the top n domains looked up, by the number of DNS queries for them.

    Args:
        packets (list): List of Packet objects.
        n (int): Number of top domains to return. Default is 10.

    Returns:
        list: A list of tuples containing the domain and its query count, sorted by count in descending order.
    """
    counts = {}
    for packet in dns_queries(packets):
        domain = packet.dns.query
        if domain in counts:
            counts[domain] += 1
        else:
            counts[domain] = 1
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_counts[:n]

def dns_query_types(packets):
    """
    Counts the DNS queries for each record type (e.g., A for IPv4 addresses, AAAA for IPv6).

    Args:
        packets (list): List of Packet objects.

    Returns:
        dict: A dictionary with record types as keys and their respective query counts as values.
    """
    counts = {}
    for packet in dns_queries(packets):
        query_type = packet.dns.query_type
        if query_type in counts:
            counts[query_type] += 1
        else:
            counts[query_type] = 1
    return counts

def failed_dns_lookups(packets):
    """
    Finds DNS lookups that didn't succeed. Any response code other than NOERROR counts as a failure,
    e.g., NXDOMAIN (domain doesn't exist), SERVFAIL, or REFUSED.

    Args:
        packets (list): List of Packet objects.

    Returns:
        list: A list of tuples containing (domain, response code) and its count, sorted by count in descending order.
            Unlike the top_ functions, this returns every failure.
    """
    counts = {}
    for packet in dns_responses(packets):
        if packet.dns.rcode == "NOERROR":
            continue
        failure = (packet.dns.query, packet.dns.rcode)
        if failure in counts:
            counts[failure] += 1
        else:
            counts[failure] = 1
    return sorted(counts.items(), key=lambda item: item[1], reverse=True)

def dns_servers(packets, n=5):
    """
    Finds the top n DNS servers, by the number of queries sent to them.

    Args:
        packets (list): List of Packet objects.
        n (int): Number of top servers to return. Default is 5.

    Returns:
        list: A list of tuples containing the server IP and its query count, sorted by count in descending order.
    """
    counts = {}
    for packet in dns_queries(packets):
        server = packet.dst
        if server is None:
            continue
        if server in counts:
            counts[server] += 1
        else:
            counts[server] = 1
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_counts[:n]

def dns_response_times(packets):
    """
    Collects how long DNS servers took to answer.

    Args:
        packets (list): List of Packet objects.

    Returns:
        list: Response times in seconds, for the responses whose query was also captured.
    """
    return [packet.dns.response_time for packet in dns_responses(packets) if packet.dns.response_time is not None]

# ---- TCP ----

def tcp_handshake_identifier(packets):
    """
    Identifies completed TCP handshakes (SYN, SYN-ACK, ACK) in the packet data.
    tcp_connections() also finds handshakes (its handshake field), along with ports, direction, and how each connection ended.

    Args:
        packets (list): List of Packet objects.

    Returns:
        list: A list of tuples representing completed handshakes, each tuple containing (src, dst).
    """
    handshakes = []

    # Both dictionaries are keyed by connection, written from the client's side:
    # (client IP, client port, server IP, server port). Ports are included so that
    # several connections between the same two hosts are kept apart.
    syn_packets = {}
    syn_ack_packets = {}

    for packet in packets:
        conn = (packet.src, packet.src_port, packet.dst, packet.dst_port)
        reverse = (packet.dst, packet.dst_port, packet.src, packet.src_port)

        if 'SYN' in packet.flags and 'ACK' not in packet.flags:
            # client -> server
            syn_packets[conn] = packet
        elif 'SYN' in packet.flags and 'ACK' in packet.flags:
            # server -> client, so the connection is this packet's reverse
            if reverse in syn_packets:
                syn_ack_packets[reverse] = packet
        elif 'ACK' in packet.flags:
            # client -> server, completing the handshake
            if conn in syn_ack_packets:
                handshakes.append((packet.src, packet.dst))
                # Remove the packets from the dictionaries to avoid counting them again
                del syn_packets[conn]
                del syn_ack_packets[conn]

    return handshakes

@dataclass
class TcpConnection:
    """Summary of one TCP connection. The client is the side that started it (sent the SYN)."""
    client: str
    client_port: str
    server: str
    server_port: str
    start: Any                     # timestamp of the connection's first packet
    end: Any                       # timestamp of its last packet
    packets: int = 0
    bytes_from_client: int = 0     # bytes are whole frame lengths, including headers, not just the data sent
    bytes_from_server: int = 0
    handshake: bool = False        # True once SYN, SYN-ACK, and ACK have all been seen
    status: str = "open"           # "closed" (a FIN seen from either side), "reset" (RST seen), or "open" (neither)
    syn_seen: bool = False         # handshake progress, used while building the summary
    syn_ack_seen: bool = False

    @property
    def bytes(self):
        return self.bytes_from_client + self.bytes_from_server

    @property
    def duration(self):
        return self.end - self.start

def tcp_connections(packets):
    """
    Groups TCP packets into connections and summarizes each one.

    Args:
        packets (list): List of Packet objects.

    Returns:
        list: A list of TcpConnection objects, in the order the connections started.
    """
    connections = []
    # the latest connection for each (client IP, client port, server IP, server port)
    by_key = {}

    for packet in packets:
        if packet.transport != 'TCP' or packet.src is None:
            continue
        conn = (packet.src, packet.src_port, packet.dst, packet.dst_port)
        reverse = (packet.dst, packet.dst_port, packet.src, packet.src_port)
        is_syn = 'SYN' in packet.flags and 'ACK' not in packet.flags
        is_syn_ack = 'SYN' in packet.flags and 'ACK' in packet.flags

        # find the connection this packet belongs to, and which way it's going
        if conn in by_key:
            connection, from_client = by_key[conn], True
        elif reverse in by_key:
            connection, from_client = by_key[reverse], False
        else:
            connection, from_client = None, None

        # A new SYN after a connection got going means the client port is being reused for a new connection.
        # Before the handshake finishes, a repeated SYN is just the client retrying, so it stays in the same connection.
        if connection is not None and is_syn and (connection.handshake or connection.status != "open"):
            connection = None

        if connection is None:
            # Work out which side is the client. The SYN and SYN-ACK say so directly; for a connection
            # that started before the capture did, guess that the server is the side with the lower port.
            if is_syn:
                from_client = True
            elif is_syn_ack:
                from_client = False
            else:
                from_client = int(packet.dst_port) <= int(packet.src_port)
            key = conn if from_client else reverse
            connection = TcpConnection(*key, start=packet.timestamp, end=packet.timestamp)
            by_key[key] = connection
            connections.append(connection)

        connection.end = packet.timestamp
        connection.packets += 1
        if from_client:
            connection.bytes_from_client += packet.length
        else:
            connection.bytes_from_server += packet.length

        # handshake: SYN from the client, SYN-ACK from the server, then ACK from the client
        if is_syn and from_client:
            connection.syn_seen = True
        elif is_syn_ack and not from_client and connection.syn_seen:
            connection.syn_ack_seen = True
        elif 'ACK' in packet.flags and from_client and connection.syn_ack_seen:
            connection.handshake = True

        # RST wins: it marks the connection reset even after a FIN, and a later FIN doesn't undo it
        if 'RST' in packet.flags:
            connection.status = "reset"
        elif 'FIN' in packet.flags and connection.status == "open":
            connection.status = "closed"

    return connections

def top_server_ports(connections, n=10):
    """
    Finds the top n server ports by the number of connections to them, which shows the services in use
    (e.g., 443 for HTTPS, 22 for SSH).

    Args:
        connections (list): List of TcpConnection objects, from tcp_connections().
        n (int): Number of top ports to return. Default is 10.

    Returns:
        list: A list of tuples containing the port and its connection count, sorted by count in descending order.
    """
    counts = {}
    for connection in connections:
        port = connection.server_port
        if port in counts:
            counts[port] += 1
        else:
            counts[port] = 1
    sorted_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return sorted_counts[:n]
