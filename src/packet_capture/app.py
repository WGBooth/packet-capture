"""
Filename: app.py
Description: Streamlit GUI for capturing and analyzing network packets.
Run with: streamlit run src/packet_capture/app.py
"""
import asyncio
import tempfile
import time
from collections import Counter

import pandas as pd
import streamlit as st

from packet_capture.capture import (capture_live, capture_remote, capture_file,
                                    list_live_interfaces, list_remote_interfaces)
from packet_capture.packet import Packet
from packet_capture.session import CaptureSession
import packet_capture.analysis as ana

# Gives Streamlit's script thread an asyncio event loop, which pyshark uses. This is possibly unneeded,
# since pyshark creates its own loop when it runs outside the main thread.
try:
    asyncio.get_event_loop()
except RuntimeError:
    asyncio.set_event_loop(asyncio.new_event_loop())


@st.cache_data(show_spinner="Reading capture file...")
def load_file(file_bytes):
    """
    Reads an uploaded capture file into a list of Packet objects.

    Cached by the file's contents, so reruns and re-uploading the same file don't parse it again.
    """
    # pyshark needs a path on disk, so write the upload to a temp file first. The .pcapng suffix
    # is fine for .pcap uploads too, since tshark checks the file's contents, not its name.
    with tempfile.NamedTemporaryFile(suffix=".pcapng") as tmp:
        tmp.write(file_bytes)
        tmp.flush()
        file_capture = capture_file(tmp.name)
        packets = [Packet(raw_packet) for raw_packet in file_capture]
        file_capture.close()
    return packets


@st.cache_data(ttl=60, show_spinner="Finding interfaces...")
def get_interfaces(remote_host=None):
    """
    Lists the interfaces on this machine, or on remote_host, as (name, description) tuples.

    Cached for 60 seconds so the list isn't looked up again on every rerun.
    Errors aren't cached, so a failed lookup is retried.
    """
    if remote_host:
        return list_remote_interfaces(remote_host)
    return list_live_interfaces()


def interface_picker(remote_host=None):
    """
    Shows a dropdown of the interfaces on this machine (or remote_host) and returns the chosen name.
    Falls back to a text box if they can't be listed.
    """
    try:
        interfaces = get_interfaces(remote_host)
    except Exception as e:
        st.warning(f"Couldn't list interfaces: {e}")
        interfaces = []
    if not interfaces:
        return st.text_input("Interface", "en0")

    descriptions = dict(interfaces)
    names = list(descriptions)
    # start on the usual main interface (macOS: en0, Linux: eth0 or wlan0), or the first one listed
    default = next((names.index(name) for name in ("en0", "eth0", "wlan0") if name in names), 0)
    col1, col2 = st.columns([5, 1], vertical_alignment="bottom")
    interface = col1.selectbox("Interface", names, index=default,
                               format_func=lambda name: f"{name} ({descriptions[name]})" if descriptions[name] else name)
    if col2.button("↻", help="Refresh the interface list"):
        get_interfaces.clear()
        st.rerun()
    return interface


def packet_table(packets):
    """
    Makes a table with one row per packet. The columns are Packet's attributes, so a new Packet
    field shows up here automatically. DNS details have their own tab, so they're left out.
    """
    return pd.DataFrame([{name: value for name, value in vars(p).items() if name != "dns"} for p in packets])


def capture_limit():
    """
    Shows the sidebar inputs for when to stop: after a set number of packets, or when the user clicks Stop.
    Returns the number of packets, or None to run until Stop is clicked.
    """
    stop_when = st.radio("Stop capture", ["After a number of packets", "When I click Stop"])
    if stop_when == "After a number of packets":
        return st.number_input("Packets to capture", min_value=1, value=100)
    return None


@st.fragment(run_every=1)
def show_capture_progress():
    """
    Shows the packet count, elapsed time, Stop button, and latest packets while a capture is going.

    As a fragment, it reruns every second on its own without rerunning the whole page. Rerunning the
    whole page every second would redo all the analysis and could reset widgets the user is using.
    """
    session = st.session_state.capture_session

    if not session.running:
        # capture finished: hand the packets to the analysis and redraw the whole page
        if session.error:
            st.session_state.capture_error = session.error
        st.session_state.packets = session.packets
        del st.session_state.capture_session
        st.rerun()

    if session.stopping:
        session.stop()  # keep asking in case the capture hadn't started its processes yet

    elapsed = time.time() - session.start_time
    col1, col2, col3 = st.columns([1, 1, 2])
    col1.metric("Packets captured", f"{len(session.packets):,}" + (f" / {session.limit:,}" if session.limit else ""))
    col2.metric("Elapsed", f"{int(elapsed // 60)}:{int(elapsed % 60):02d}")
    with col3:
        if st.button("Stop capture", type="primary", disabled=session.stopping):
            session.stop()
        if session.stopping:
            st.caption("Stopping...")

    st.subheader("Latest packets")
    # the last 20, shown newest first
    latest = session.packets[-20:]
    if latest:
        st.dataframe(packet_table(reversed(latest)), hide_index=True)
    else:
        st.caption("Waiting for packets...")


# Bucket sizes for the traffic chart, smallest first: (pandas frequency, label)
TRAFFIC_INTERVALS = [("1s", "second"), ("10s", "10 seconds"), ("1min", "minute"), ("10min", "10 minutes"),
                     ("1h", "hour"), ("1D", "day"), ("7D", "week"), ("30D", "30 days")]


def traffic_interval(span, max_buckets=500):
    """
    Picks the smallest bucket size from TRAFFIC_INTERVALS that keeps the chart under max_buckets points,
    for a capture lasting span (a pandas Timedelta). Returns (pandas frequency, label).

    Grouping a long capture by second can make millions of points, which is too much to send to the browser.
    """
    for freq, label in TRAFFIC_INTERVALS:
        if span / pd.Timedelta(freq) <= max_buckets:
            return freq, label
    return TRAFFIC_INTERVALS[-1]


def packet_filters(packets):
    """
    Shows the protocol, IP, and port filter dropdowns above the analysis and returns the matching packets.

    Options come from the whole capture, most common first, with their packet counts. They aren't narrowed
    by the other filters, so picking a protocol doesn't shrink the IP list.
    """
    # Each packet's addresses and ports go in a set, so a packet sent to itself is only counted once.
    # "if ip" / "if port" skip None (packets without IP or ports).
    protocols = Counter(p.protocol for p in packets)
    ips = Counter(ip for p in packets for ip in {p.src, p.dst} if ip)
    ports = Counter(str(port) for p in packets for port in {p.src_port, p.dst_port} if port)

    def options(counts):
        return [value for value, _ in counts.most_common()]

    st.subheader("Filters")
    col1, col2, col3 = st.columns(3)
    selected_protocols = col1.multiselect("Protocol", options(protocols), placeholder="All protocols",
                                          format_func=lambda value: f"{value} ({protocols[value]:,})")
    selected_ips = col2.multiselect("IP address", options(ips), placeholder="All IP addresses",
                                    format_func=lambda value: f"{value} ({ips[value]:,})",
                                    help="Matches packets to or from these addresses")
    selected_ports = col3.multiselect("Port", options(ports), placeholder="All ports",
                                      format_func=lambda value: f"{value} ({ports[value]:,})",
                                      help="Matches packets with these as the source or destination port")

    filtered = ana.filter_packets(packets, selected_protocols, selected_ips, selected_ports)
    if len(filtered) < len(packets):
        st.caption(f"Showing {len(filtered):,} of {len(packets):,} packets")
    return filtered


def show_analysis(packets):
    """
    Shows the analysis of packets in three tabs. Streamlit builds every tab on each rerun,
    not just the one being looked at.
    """
    overview, dns, tcp = st.tabs(["Overview", "DNS", "TCP"])
    with overview:
        show_overview(packets)
    with dns:
        show_dns(packets)
    with tcp:
        show_tcp(packets)


def show_overview(packets):
    """
    Overview tab: totals, protocol counts, top hosts, ports, and conversations, traffic over time,
    and a table of every packet.
    """
    total_packets, total_bytes = ana.totals(packets)
    col1, col2 = st.columns(2)
    col1.metric("Total packets", f"{total_packets:,}")
    col2.metric("Total bytes", f"{total_bytes:,}")

    st.subheader("Protocol counts")
    protocols = pd.Series(ana.protocol_counts(packets), name="packets").sort_values(ascending=False)
    st.bar_chart(protocols, horizontal=True)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Top hosts")
        st.dataframe(pd.DataFrame(ana.top_hosts(packets), columns=["host", "packets"]), hide_index=True)
    with col2:
        st.subheader("Top ports")
        st.dataframe(pd.DataFrame(ana.top_ports(packets), columns=["port", "packets"]), hide_index=True)

    st.subheader("Top conversations")
    convos = [(src, dst, count) for (src, dst), count in ana.top_conversations(packets)]
    st.dataframe(pd.DataFrame(convos, columns=["source", "destination", "packets"]), hide_index=True)

    st.subheader("Traffic over time")
    traffic = pd.Series(ana.traffic_over_time(packets), name="packets")
    traffic.index = pd.to_datetime(traffic.index)
    freq, label = traffic_interval(traffic.index.max() - traffic.index.min())
    st.caption(f"Packets per {label}")
    st.line_chart(traffic.resample(freq).sum())

    with st.expander("All packets"):
        st.dataframe(packet_table(packets), hide_index=True)


# How a TCP connection ended, as shown in the connections table
TCP_STATUS_LABELS = {"closed": "Closed (FIN)", "reset": "Reset (RST)", "open": "Open"}


def show_tcp(packets):
    """
    TCP tab: connection counts by how they ended, the top server ports, and a table of every connection.
    """
    connections = ana.tcp_connections(packets)
    if not connections:
        st.info("No TCP traffic in these packets.")
        return

    statuses = Counter(connection.status for connection in connections)
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Connections", f"{len(connections):,}")
    col2.metric("Completed handshakes", f"{sum(connection.handshake for connection in connections):,}",
                help="Connections where the SYN, SYN-ACK, and ACK were all captured")
    col3.metric("Closed (FIN)", f"{statuses['closed']:,}")
    col4.metric("Reset (RST)", f"{statuses['reset']:,}")
    col5.metric("Still open", f"{statuses['open']:,}", help="No FIN or RST by the end of the capture")

    col1, col2 = st.columns([1, 3])
    with col1:
        st.subheader("Top server ports")
        st.dataframe(pd.DataFrame(ana.top_server_ports(connections), columns=["port", "connections"]), hide_index=True)
    with col2:
        st.subheader("Connections")
        rows = [{
            "client": c.client,
            "client port": c.client_port,
            "server": c.server,
            "server port": c.server_port,
            "start": c.start,
            "duration (s)": c.duration.total_seconds(),
            "packets": c.packets,
            "bytes sent": c.bytes_from_client,
            "bytes received": c.bytes_from_server,
            "handshake": c.handshake,
            "ended": TCP_STATUS_LABELS[c.status],
        } for c in sorted(connections, key=lambda c: c.bytes, reverse=True)]
        st.dataframe(pd.DataFrame(rows), hide_index=True)
        st.caption("Largest first; click a column to sort. Bytes sent and received are from the client's side.")


def show_dns(packets):
    """
    DNS tab: query and response counts, failed lookups, response time, top domains, query types,
    DNS servers, and a table of every response.
    """
    queries = ana.dns_queries(packets)
    responses = ana.dns_responses(packets)
    if not queries and not responses:
        st.info("No DNS traffic in these packets.")
        return

    failed = ana.failed_dns_lookups(packets)
    response_times = ana.dns_response_times(packets)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Queries", f"{len(queries):,}")
    col2.metric("Responses", f"{len(responses):,}")
    col3.metric("Failed lookups", f"{sum(count for _, count in failed):,}")
    col4.metric("Median response time", f"{pd.Series(response_times).median() * 1000:.1f} ms" if response_times else "–",
                help="How long servers took to answer, for responses whose query was also captured")

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Top domains")
        st.dataframe(pd.DataFrame(ana.top_domains(packets), columns=["domain", "queries"]), hide_index=True)
    with col2:
        st.subheader("Query types")
        query_types = pd.Series(ana.dns_query_types(packets), name="queries").sort_values(ascending=False)
        st.bar_chart(query_types, horizontal=True)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Failed lookups")
        if failed:
            rows = [(domain, rcode, count) for (domain, rcode), count in failed]
            # fit the table to its rows (38px header + 35px per row), up to 400px
            st.dataframe(pd.DataFrame(rows, columns=["domain", "result", "responses"]), hide_index=True,
                         height=min(400, 38 + 35 * len(rows)))
        else:
            st.caption("Every lookup succeeded.")
    with col2:
        st.subheader("DNS servers")
        st.dataframe(pd.DataFrame(ana.dns_servers(packets), columns=["server", "queries"]), hide_index=True)

    with st.expander("All DNS responses"):
        rows = [{
            "timestamp": p.timestamp,
            "server": p.src,
            "client": p.dst,
            "domain": p.dns.query,
            "type": p.dns.query_type,
            "result": p.dns.rcode,
            "answers": ", ".join(p.dns.answers),
            "response time (ms)": p.dns.response_time * 1000 if p.dns.response_time is not None else None,
        } for p in responses]
        st.dataframe(pd.DataFrame(rows), hide_index=True)


# ---- Page ----
# Streamlit runs everything below from the top on every interaction (a "rerun"). The sidebar picks
# where packets come from; the main area shows a capture in progress or the analysis.

st.set_page_config(page_title="Packet Analyzer", layout="wide")
st.title("Packet Capture and Analyzer")

# Sidebar: choose a capture mode and its inputs
with st.sidebar:
    st.header("Capture")
    mode = st.radio("Capture mode", ["File", "Live", "Remote"])

    if mode == "File":
        uploaded = st.file_uploader("Capture file", type=["pcap", "pcapng"])
        if uploaded is not None:
            st.session_state.packets = load_file(uploaded.getvalue())

    else:
        capturing = "capture_session" in st.session_state
        # CaptureSession gets a function (the lambda) instead of a capture, since it has to create the
        # capture in its own thread; pyshark ties a capture to the thread that creates it.
        # st.rerun() switches the main area to the progress view straight away and disables Start.
        if mode == "Live":
            interface = interface_picker()
            limit = capture_limit()
            if st.button("Start capture", disabled=capturing):
                st.session_state.capture_session = CaptureSession(lambda: capture_live(interface), limit)
                st.rerun()

        elif mode == "Remote":
            remote_host = st.text_input("Remote host", placeholder="username@192.168.86.1")
            if remote_host:
                interface = interface_picker(remote_host)
            else:
                interface = st.selectbox("Interface", [], disabled=True, placeholder="Enter a remote host first")
            limit = capture_limit()
            if st.button("Start capture", disabled=capturing or not remote_host):
                st.session_state.capture_session = CaptureSession(lambda: capture_remote(remote_host, interface), limit)
                st.rerun()

# Main area: results. session_state keeps the packets across Streamlit reruns.
if "capture_error" in st.session_state:
    # pop() removes the error as it's shown, so it's only shown once
    st.error(f"Capture failed: {st.session_state.pop('capture_error')}")

packets = st.session_state.get("packets")
if "capture_session" in st.session_state:
    show_capture_progress()
elif packets:
    filtered = packet_filters(packets)
    if filtered:
        show_analysis(filtered)
    else:
        st.info("No packets match the filters.")
else:
    st.info("Choose a capture mode in the sidebar to get started.")
