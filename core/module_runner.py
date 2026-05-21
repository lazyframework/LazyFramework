import subprocess
import os
import signal
import threading
from contextlib import redirect_stdout, redirect_stderr
from PyQt6.QtCore import QThread, pyqtSignal, Qt
from .capture import UniversalCapture

class PatchedPopen(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        # pop output_callback if ada (ModuleRunner memberikan)
        self.output_callback = kwargs.pop('output_callback', None)

        # Force capture output (text mode)
        kwargs.setdefault('stdout', subprocess.PIPE)
        kwargs.setdefault('stderr', subprocess.STDOUT)
        kwargs.setdefault('universal_newlines', True)
        kwargs.setdefault('bufsize', 1)

        # Ensure process group created for safe killing
        if os.name == 'posix':
            kwargs.setdefault('preexec_fn', os.setsid)
        else:
            # Windows flag
            kwargs.setdefault('creationflags', getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))

        super().__init__(*args, **kwargs)

        # Spawn thread to read stdout (daemon so it won't block exit)
        if self.output_callback and self.stdout:
            self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self._reader_thread.start()

    def _read_output(self):
        try:
            # read line by line; stop when stream closed
            for line in iter(self.stdout.readline, ''):
                if not line:
                    break
                try:
                    # callback is expected to be Qt signal emit or similar;
                    # ensure it doesn't raise to this thread
                    self.output_callback(line.rstrip())
                except Exception:
                    pass
        except Exception:
            pass


class ModuleRunner(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, framework, module_instance):
        super().__init__()
        self.framework = framework
        self.module_instance = module_instance

        # capture object used with contextlib.redirect_stdout/stderr
        self.capture = UniversalCapture()
        # ensure queued connection so emit from any thread is queued to main
        #self.capture.output_signal.connect(self.output.emit, Qt.QueuedConnection)
        self.capture.output_signal.connect(self.output.emit, Qt.ConnectionType.QueuedConnection)
        self.original_popen = subprocess.Popen
        self.original_system = os.system

        self._stop_flag = False
        self._active = []
        self._lock = threading.Lock()
        self._listeners = []  # track ReverseTCPListener instances

    def register_listener(self, listener):
        """Daftarkan listener agar bisa dihentikan saat stop()"""
        with self._lock:
            self._listeners.append(listener)

    def stop(self):
        self._stop_flag = True

        self.output.emit("[yellow]Runner stop requested — terminating children...[/]")

        # Stop semua ReverseTCPListener yang terdaftar
        with self._lock:
            listeners = list(self._listeners)

        for listener in listeners:
            try:
                listener.running = False
                if hasattr(listener, 'server_socket') and listener.server_socket:
                    try:
                        import socket as _socket
                        listener.server_socket.shutdown(_socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        listener.server_socket.close()
                        listener.server_socket = None
                    except Exception:
                        pass
            except Exception:
                pass

        with self._lock:
            self._listeners.clear()

        # Kill tracked child processes
        with self._lock:
            procs = list(self._active)

        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
            try:
                p.wait(timeout=0.3)
            except Exception:
                try:
                    if os.name == 'posix' and hasattr(os, "killpg"):
                        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                    else:
                        p.kill()
                except Exception:
                    try:
                        p.kill()
                    except Exception:
                        pass

        with self._lock:
            self._active.clear()

    def run(self):
        #from contextlib import redirect_stdout, redirect_stderr
        try:
            # Bind patched Popen & system local to this thread's duration
            subprocess.Popen = self._patched_popen
            os.system = self._patched_system

            # Use contextlib.redirect_stdout/stderr to capture prints only for duration of module
            # This reduces window where global stdout is replaced
            try:
                with redirect_stdout(self.capture), redirect_stderr(self.capture):
                    if not self._stop_flag:
                        # Run module (this runs inside this QThread)
                        self.module_instance.run(self.framework.session)
            except Exception as e:
                # Module-level exceptions => emit to GUI
                self.output.emit(f"[red]Module Error: {e}[/red]")

        except Exception as e:
            self.output.emit(f"[red]Runner fatal error: {e}[/red]")

        finally:
            # restore globals
            try:
                subprocess.Popen = self.original_popen
            except Exception:
                pass
            try:
                os.system = self.original_system
            except Exception:
                pass

            # ensure any leftover procs cleaned
            with self._lock:
                self._active.clear()

            # stop capture (no-op here because redirect already restored)
            try:
                self.capture.flush()
            except Exception:
                pass

            # notify GUI that we're finished
            self.finished.emit()

    def _patched_popen(self, *args, **kwargs):
        # ensure callback present
        kwargs['output_callback'] = self.output.emit

        # preserve user's requested creation flags if any; we already set defaults in PatchedPopen
        try:
            p = PatchedPopen(*args, **kwargs)
        except TypeError:
            # fallback to original Popen if signature mismatch
            p = self.original_popen(*args, **kwargs)

        with self._lock:
            self._active.append(p)
        return p

    def _patched_system(self, cmd):
        # use our patched Popen to execute command
        self.output.emit(f"$ {cmd}")
        p = self._patched_popen(cmd, shell=True)
        try:
            p.wait()
        except Exception:
            pass
        return getattr(p, "returncode", -1)