import os
import signal
import threading
import logging

logger = logging.getLogger(__name__)


class Timeout:
    def __init__(self, timeout=180):
        self.timeout = timeout
        self._t = None

    def do_expire(self):
        os.kill(os.getpid(), signal.SIGTERM)

    def _expire(self):
        print("\nSession timed out due to inactivity")
        self.do_expire()

    def start(self):
        if self._t is None:
            self._t = threading.Timer(self.timeout, self._expire)
            self._t.start()

    def stop(self):
        if self._t is not None:
            self._t.cancel()
            self._t = None

    def refresh(self):
        if self._t is not None:
             self.stop()
             self.start()