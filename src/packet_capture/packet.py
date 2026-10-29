"""
Filename: packet.py
Description: Creates a custom packet object for network analysis
"""
from dataclasses import dataclass, field

"""
# TCP flag names and their bits in flags field #
FIN - 0x01 - Finish - end of connection
SYN - 0x02 - Synchronize - initiate connection
RST - 0x04 - Reset - aborts the connection
PSH - 0x08 - Push - pushes data without waiting for the buffer to be full
ACK - 0x10 - Acknowledgment - confirms data (or the SYN) was received
URG - 0x20 - Urgent - indicates urgent data to be prioritized
"""
TCP_FLAGS = (("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04), ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20))

"""
# DNS response codes #
-- https://www.dnslab.dev/learn/docs/reference/response-codes --
-- Base Response Code --
NoError - 0 - No error condition - All's good!
FormErr - 1 - Format error - Improperly formatted query
ServFail - 2 - Server failure - The server encountered an internal error
NXDomain - 3 - Non-existent domain - The domain name does not exist
NotImp - 4 - Not implemented - The server does not support the requested operation
Refused - 5 - Query refused - The server refused to answer for policy reasons
"""
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

@dataclass
class DnsInfo:
    """
    DNS details for a packet

    query: domain name e.g. "mlb.com"
    query_type: record type
        A - IPv4 address record
        AAAA - IPv6 address record
        PTR - reverse lookup (IP address to domain name)
    is_response: (True) - DNS response / (False) - DNS query
    rcode: result of a response
        DNS_RCODES above
        None for queries
    answers: list of IP addresses returned, can be IPv4 or IPv6
    response_time: time since matching query (seconds)
        None if tshark didn't see the matching query
    """
    query: str | None
    query_type: str | None
    is_response: bool
    rcode: str | None = None
    answers: list = field(default_factory=list)
    response_time: float | None = None

    @classmethod
    def from_pyshark(cls, dns_layer):
        """
        Build a DnsInfo from a pyshark DNS layer
        """
        query_type = dns_layer.get_field("qry_type")
        rcode = dns_layer.get_field("flags_rcode")
        response_time = dns_layer.get_field("time")

        # loops through to make a list of IP addresses (A and AAAA)
        answers = []
        for record in ("a", "aaaa"):
            values = dns_layer.get_field(record)
            if values is not None:
                answers += [value.get_default_value() for value in values.all_fields]

        is_response = dns_layer.flags_response == "True"
        return cls(
            query=dns_layer.get_field("qry_name"),
            # Wireshark labels types like "A (1) (Host Address)", so keep the first word
            query_type=query_type.showname_value.split(" ")[0] if query_type is not None else None,
            is_response=is_response,
            rcode=DNS_RCODES.get(int(rcode), rcode.showname_value) if is_response and rcode is not None else None,
            answers=answers,
            response_time=float(response_time) if response_time is not None else None,
        )

class Packet:
    """The fields of a captured packet that the analysis uses"""
    def __init__(self, raw_packet):
        self.timestamp = raw_packet.sniff_time

        # source and destination IP addresses, None for those without IP
        ip_layer = raw_packet.ip if 'IP' in raw_packet else (raw_packet.ipv6 if 'IPV6' in raw_packet else None)
        self.src = ip_layer.src if ip_layer is not None else None
        self.dst = ip_layer.dst if ip_layer is not None else None

        # protocol of the packet (e.g., TCP, UDP, ICMP)
        self.protocol = raw_packet.highest_layer
        
        # transport protocol ('TCP' or 'UDP'), or None for packets without one (e.g., ARP, ICMP)
        self.transport = raw_packet.transport_layer

        # port numbers from the TCP or UDP layer, or None for packets without one (e.g., ARP, ICMP)
        self.src_port = raw_packet['TCP'].srcport if 'TCP' in raw_packet else (raw_packet['UDP'].srcport if 'UDP' in raw_packet else None)
        self.dst_port = raw_packet['TCP'].dstport if 'TCP' in raw_packet else (raw_packet['UDP'].dstport if 'UDP' in raw_packet else None)
        self.length = int(raw_packet.length)

        # TCP flags that are set (e.g., ['SYN', 'ACK']), or an empty list for non-TCP packets
        if 'TCP' in raw_packet:
            # tshark gives flags as a hex string, e.g. "0x0012" for SYN+ACK
            bits = int(raw_packet.tcp.flags, 16)
            self.flags = [name for name, mask in TCP_FLAGS if bits & mask]
        else:
            self.flags = []

        # DNS query or response details, or None for packets without DNS
        self.dns = DnsInfo.from_pyshark(raw_packet.dns) if 'DNS' in raw_packet else None

    def __repr__(self):
        return f"Packet(timestamp={self.timestamp}, src={self.src}, dst={self.dst}, protocol={self.protocol}, transport={self.transport}, src_port={self.src_port}, dst_port={self.dst_port}, length={self.length}, flags={self.flags}, dns={self.dns})"
