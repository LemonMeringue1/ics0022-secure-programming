import os
import signal
import threading
import logging

logger = logging.getLogger(__name__)


class Timeout:
    def __init__(self, timeout=180, on_expire=None):
        self.timeout = timeout
        self._on_expire = on_expire
        self._t = None

    def do_expire(self):
        logger.info("session_timed_out")
        if self._on_expire is not None:
            try:
                self._on_expire()
            except Exception as e:
                logger.error("expire_cleanup_failed type=%s", type(e).__name__)
        os._exit(1)

    def _expire(self):
        print("\nSession timed out due to inactivity")
        self.do_expire()

    def start(self):
        if self._t is None:
            self._t = threading.Timer(self.timeout, self._expire)
            self._t.daemon = True
            self._t.start()

    def stop(self):
        if self._t is not None:
            self._t.cancel()
            self._t = None

    def refresh(self):
        if self._t is not None:
             self.stop()
             self.start()