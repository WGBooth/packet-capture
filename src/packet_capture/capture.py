"""
Filename: capture.py
Description: Captures network packets from a .pcapng file, a live network interface, or a remote host
             (over ssh) using pyshark, and lists the interfaces available to capture on.
"""
import re
import subprocess
import pyshark as shark
from pyshark.capture.capture import Capture
from pyshark.capture.pipe_capture import PipeCapture
from pyshark.tshark.tshark import get_process_path

# Matches a line from "tshark -D" ("4. en0 (Wi-Fi)") or "tcpdump -D" ("4.en0 [Up, Running]",
# or on Linux "2.any (Pseudo-device that captures on all interfaces) [Up, Running]").
# The three groups are the name, the (description), and the [status]; the last two are optional.
_INTERFACE_LINE = re.compile(r"^\d+\.\s*(\S+)\s*(?:\((.*)\))?\s*(?:\[(.*)\])?")

class RemoteCapture(PipeCapture):
    """PipeCapture that reads from an ssh + tcpdump process and stops it when closed."""
    def __init__(self, ssh_process, **kwargs):
        super().__init__(pipe=ssh_process.stdout, **kwargs)
        self.ssh_process = ssh_process

    def close(self):
        # PipeCapture.close() calls os.close() on the pipe, which only works on a file descriptor,
        # not the file object from Popen, so skip it and stop the ssh process ourselves
        Capture.close(self)
        # stopping ssh drops the connection, which also stops tcpdump on the remote host
        self.ssh_process.terminate()
        # wait for ssh to exit, so it doesn't linger as a dead ("zombie") process
        self.ssh_process.wait()
        # release the pipe
        self.ssh_process.stdout.close()

def capture_live(interface):
    """
    Sets up a live capture on a network interface of this computer, e.g. "en0".
    Nothing is captured until the result is looped over.
    """
    return shark.LiveCapture(interface=interface)

def capture_remote(remote_host, interface):
    """
    Sets up a capture on a network interface of remote_host, by running tcpdump there over ssh.
    Nothing is captured until the result is looped over.

    If ssh or tcpdump fails (e.g., a bad host or no permission to capture), the capture is just empty;
    the error is printed in the terminal running the app, not shown in the app.
    """
    # tcpdump options:
    #   -i {interface}  the interface to capture on - e.g., "en0" for Wi-Fi on macOS
    #   -U              write each packet as soon as it arrives
    #   -w -            write raw packets
    #   'not port 22'   exclude SSH traffic to avoid capturing the packets carrying the capture itself
    ssh_cmd = ["ssh", remote_host, f"tcpdump -i {interface} -U -w - 'not port 22'"]
    proc = subprocess.Popen(ssh_cmd, stdout=subprocess.PIPE)
    # macOS-only path to tshark; get_process_path() would find it on any OS
    return RemoteCapture(proc, tshark_path="/Applications/Wireshark.app/Contents/MacOS/tshark")

def capture_file(my_file):
    """
    Opens a capture file (.pcap or .pcapng) to read packets from.
    Raises FileNotFoundError straight away if the file doesn't exist.
    """
    return shark.FileCapture(my_file)

def _parse_interfaces(output):
    """Turns the output of "tshark -D" or "tcpdump -D" into a list of (name, description) tuples."""
    interfaces = []
    for line in output.splitlines():
        match = _INTERFACE_LINE.match(line.strip())
        if match:
            name, description, status = match.groups()
            # join whichever parts are present, e.g. "Wi-Fi" from tshark, or
            # "Pseudo-device that captures on all interfaces · Up, Running" from Linux tcpdump
            interfaces.append((name, " · ".join(part for part in (description, status) if part)))
    return interfaces

# Interfaces for a live capture
def list_live_interfaces():
    """Returns (name, description) for each interface tshark can capture on, e.g. ("en0", "Wi-Fi")."""
    result = subprocess.run([get_process_path(), "-D"], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"tshark exited with code {result.returncode}")
    return _parse_interfaces(result.stdout)

# Interfaces for a remote capture
def list_remote_interfaces(remote_host):
    """Returns (name, description) for each interface tcpdump can capture on at remote_host, e.g. ("eth0", "Up, Running")."""
    # ConnectTimeout gives up if the host can't be reached within 5 seconds. timeout covers everything
    # after that, e.g. ssh waiting for a password in the terminal
    # (adding "-o BatchMode=yes" would make it fail straight away instead).
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", remote_host, "tcpdump -D"]
    result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"ssh exited with code {result.returncode}")
    return _parse_interfaces(result.stdout)
