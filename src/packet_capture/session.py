"""
Filename: session.py
Description: Runs a live or remote capture in a background thread so a GUI can show progress and stop it.
"""
import os
import signal
import threading
import time
from contextlib import closing

from packet_capture.capture import RemoteCapture
from packet_capture.packet import Packet

class CaptureSession:
    """
    A live or remote capture running in a background thread, so the GUI stays responsive while it runs.

    How the app uses it:
        1. Create one; capturing starts straight away.
        2. Every second, show len(packets), and check running to see if it has finished.
        3. Call stop() when the user clicks Stop (or let it reach the limit).
        4. Once running is False, use packets, and show error if there is one.

    Attributes:
        packets (list): Packet objects captured so far. It grows while the capture runs. The app reads it
            from another thread, which is safe since the list is only ever added to.
        error (Exception): The exception that ended the capture, or None. An exception in a background
            thread would otherwise disappear silently, so it's saved here for the app to show.
        limit (int): The packet limit passed in, or None.
        start_time (float): When the session started (from time.time()), for showing the elapsed time.
    """
    def __init__(self, make_capture, limit=None):
        """
        Starts capturing in a background thread.

        Args:
            make_capture (function): Returns a new pyshark capture. It's called in the background thread,
                since pyshark ties a capture to the thread that creates it.
            limit (int): Stop after this many packets, or None to run until stop() is called.
        """
        self.limit = limit
        self.packets = []
        self.error = None
        self.start_time = time.time()
        self._make_capture = make_capture
        self._capture = None
        self._stop_requested = threading.Event()
        # daemon=True so an unfinished capture doesn't keep Python from exiting when Streamlit shuts down
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @property
    def running(self):
        """True until the capture has finished and been closed (it can still be True while stopping)."""
        return self._thread.is_alive()

    @property
    def stopping(self):
        """True once stop() has been called, even if the capture hasn't finished stopping yet."""
        return self._stop_requested.is_set()

    def stop(self):
        """
        Asks the capture to stop. It stops shortly after, not straight away; check running to see when it has.

        Safe to call repeatedly until running is False, and it may need to be: if it's called before the
        background thread has created the capture, there's nothing to stop yet. The app handles this by
        calling stop() again every second while stopping (show_capture_progress in app.py).
        """
        self._stop_requested.set()
        if self._capture is None:
            return
        # tshark blocks until the next packet arrives, so on a quiet network the flag alone could take a
        # long time to be noticed. tshark ignores SIGTERM while it waits, so instead end whatever is
        # feeding it packets (ssh for remote, dumpcap for live); tshark then reaches the end of its input
        # and the read returns.
        if isinstance(self._capture, RemoteCapture):
            self._capture.ssh_process.terminate()
            return
        # For a live capture, send SIGTERM to every process pyshark started. tshark ignores it, but dumpcap
        # (which reads the interface) exits. pyshark has no public way to get its processes, so this uses its
        # private _running_processes, which could change in a new pyshark version.
        try:
            processes = list(self._capture._running_processes)
        except RuntimeError:
            return  # the set changed while copying it; the next call will get it
        for process in processes:
            try:
                # os.kill() instead of process.kill(), which can collect the exited process out from
                # under pyshark's own thread and make it think tshark crashed
                os.kill(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def _run(self):
        """
        Runs in the background thread: creates the capture, reads packets until it ends, the limit is
        reached, or stop() is called, then closes it. Errors are saved in self.error instead of raised.
        """
        try:
            self._capture = self._make_capture()
            # pyshark's iterator is a generator. closing() makes sure its cleanup runs (stopping tshark)
            # when we break out of the loop early, instead of whenever it gets garbage collected.
            with closing(iter(self._capture)) as stream:
                for raw_packet in stream:
                    self.packets.append(Packet(raw_packet))
                    # a limit of None (or 0) means no limit
                    if self.stopping or (self.limit and len(self.packets) >= self.limit):
                        break
        except Exception as e:
            # errors caused by stop() killing the processes aren't real errors
            if not self.stopping:
                self.error = e
        finally:
            # close the capture even after an error, so tshark and ssh/dumpcap don't keep running
            if self._capture is not None:
                try:
                    self._capture.close()
                except Exception as e:
                    if not self.stopping and self.error is None:
                        self.error = e
