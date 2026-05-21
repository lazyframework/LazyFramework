#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt6.QtCore import QObject, QFileSystemWatcher, QTimer, pyqtSignal
from pathlib import Path
import sys
import shutil
import io
from contextlib import redirect_stdout, redirect_stderr


class ModuleWatcher(QObject):
    """Class terpisah untuk auto refresh modules"""
    
    modulesRefreshed = pyqtSignal()   # Signal ke GUI

    def __init__(self, framework, gui_instance=None, parent=None):
        super().__init__(parent)
        self.framework = framework
        self.gui = gui_instance
        self._watcher = None
        self._refresh_timer = None

    def start_watching(self):
        """Mulai memantau folder modules"""
        try:
            # === Cari project root dengan robust way ===
            if getattr(sys, 'frozen', False):
                # Jika di-packaging (pyinstaller)
                base_path = Path(sys.executable).parent
            else:
                # Normal execution
                base_path = Path(__file__).resolve().parent.parent.parent  # widgets -> root

            module_root = base_path / "modules"

            # Fallback jika path tidak ditemukan
            if not module_root.exists():
                possible_paths = [
                    Path.cwd() / "modules",
                    base_path / "modules",
                    Path.home() / "lazyframework" / "modules",
                    Path(__file__).resolve().parent.parent.parent / "modules"
                ]
                for p in possible_paths:
                    if p.exists():
                        module_root = p
                        break

            if not module_root.exists():
                if self.gui:
                    self.gui.append_output(f"[red]❌ Modules folder not found! Checked: {module_root}[/]")
                return False

            # Kumpulkan semua folder yang akan di-watch
            dirs_to_watch = [str(module_root)]
            for d in module_root.rglob("*"):
                if d.is_dir() and "__pycache__" not in d.parts:
                    dirs_to_watch.append(str(d.resolve()))

            dirs_to_watch = list(set(dirs_to_watch))

            # Setup QFileSystemWatcher
            self._watcher = QFileSystemWatcher(self)
            self._watcher.addPaths(dirs_to_watch)

            # Setup Timer
            self._refresh_timer = QTimer(self)
            self._refresh_timer.setSingleShot(True)
            self._refresh_timer.setInterval(1200)  # 1.2 detik debounce
            self._refresh_timer.timeout.connect(self._do_refresh)

            # Connect signals
            self._watcher.directoryChanged.connect(self._on_dir_changed)
            self._watcher.fileChanged.connect(self._on_file_changed)

            if self.gui:
                return True

        except Exception as e:
            if self.gui:
                self.gui.append_output(f"[red]ModuleWatcher error: {e}[/]")
            print(f"ModuleWatcher error: {e}")
            return False

    def _on_dir_changed(self, path):
        """Dipanggil saat folder berubah"""
        if self._refresh_timer and not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def _on_file_changed(self, path):
        """Dipanggil saat file berubah"""
        if self._refresh_timer and not self._refresh_timer.isActive():
            self._refresh_timer.start()

    def _do_refresh(self):
        """Lakukan refresh modules - dengan capture output"""
        try:
            # === CAPTURE OUTPUT DARI SCAN_MODULES ===
            output_buffer = io.StringIO()
            
            with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
                self.framework.scan_modules()
            
            # Optional: tampilkan output jika diperlukan (tapi filter pesan scanning)
            output = output_buffer.getvalue()
            if output.strip() and self.gui:
                # Filter pesan yang tidak perlu ditampilkan
                lines = output.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and '[DEBUG]' not in line:
                        # Jangan tampilkan pesan scanning module tree
                        if not line.startswith('[*] Scanning module tree'):
                            # Tampilkan dengan warna dim
                            self.gui.append_output(f"[dim]{line}[/]")
            
            # Emit signal ke GUI
            self.modulesRefreshed.emit()

            if self.gui:
                total = len(self.framework.modules)

        except Exception as e:
            if self.gui:
                self.gui.append_output(f"[red]Auto-refresh failed: {e}[/]")