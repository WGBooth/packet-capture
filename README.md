# Packet Capture and Analyzer

## Description
This program captures and analyzes network packets through a web GUI built with Streamlit. There are three different methods of capturing packets:

- **File**: upload a captured .pcap or .pcapng file
- **Live**: capture from a network interface on this machine
- **Remote**: capture from a network interface on another machine over SSH

Live and remote captures can stop after a set number of packets or run until you click Stop. IPv4 and IPv6 traffic are both supported.

After a capture, you can filter the packets by protocol, IP address, and port, and the results are shown in three tabs:

- **Overview**: total packets and bytes, protocol counts, top hosts, top ports, top conversations, traffic over time, and a table of every packet
- **DNS**: queries and responses, failed lookups (e.g. domains that don't exist), median response time, top domains, query types, and DNS servers
- **TCP**: connections with their handshakes and how they ended (closed with FIN, reset with RST, or still open), top server ports, and a table of every connection with its duration and bytes each way

## Requirements
- Python 3.11
- [Wireshark](https://www.wireshark.org/), which provides `tshark` (pyshark uses it to decode packets)
- For live capture: permission to capture on the interface. On macOS, install ChmodBPF with Wireshark.
- For remote capture: SSH access to the remote host (an SSH key is easiest), and `tcpdump` on the remote host with permission to capture

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```bash
streamlit run src/packet_capture/app.py
```
This opens the app in your browser. Choose a capture mode in the sidebar.

If you change a module other than `app.py`, restart Streamlit to load the change.

## Tests
```bash
pytest
```

## File Structure
```
src/packet_capture/
    app.py          Streamlit GUI
    capture.py      Starts file, live, and remote captures, and lists interfaces
    session.py      Runs a live or remote capture in the background so it can be stopped
    packet.py       Packet class with the fields used for analysis, including DNS details
    analysis.py     Analysis functions: general stats, filtering, DNS, and TCP connections
tests/
    test_analysis.py    Unit tests for the analysis functions, using hand-built packets
    test_capture.py     Tests reading known frames from the sample capture
    captures/           Sample capture used by the tests
```

## Technologies
- Python 3.11.4
- pyshark 0.6
- Streamlit 1.66
- pandas 3.1
- Wireshark / tshark 4.6
