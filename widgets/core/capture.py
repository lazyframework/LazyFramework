import io
import threading
from PyQt6.QtCore import QObject, pyqtSignal
# Tambahkan di top file gui.py:
# import faulthandler; faulthandler.enable(all_threads=True)
# import builtins, io, contextlib, signal

class UniversalCapture(QObject):
    output_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        # jangan simpan/ubah __builtins__ langsung; gunakan builtins module only if needed
        self._buffer = io.StringIO()
        self._lock = threading.Lock()

    def stop_capture(self):
        pass

    def write(self, text):
        # dipanggil oleh redirect_stdout/redirect_stderr atau oleh prints
        if text and text.strip():
            # melalui lock untuk safety
            with self._lock:
                try:
                    # emit sebagai string (queued connection di ModuleRunner)
                    self.output_signal.emit(str(text))
                except Exception:
                    # jangan raise di thread I/O
                    pass

    def flush(self):
        # kompatibel dengan file-like API
        try:
            with self._lock:
                self._buffer.truncate(0)
                self._buffer.seek(0)
        except Exception:
            pass

    # optional helper untuk use with redirect_stdout(self)
    def getvalue(self):
        with self._lock:
            return self._buffer.getvalue()