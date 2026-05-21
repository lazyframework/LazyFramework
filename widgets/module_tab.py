
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QScrollArea, QFormLayout, QLabel,QTabWidget,QFrame,QLineEdit,QComboBox,QMenu
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from core.module_runner import ModuleRunner


class ModuleTab(QWidget):
    """Satu tab untuk satu module yang berjalan independen."""

    _safe_append = pyqtSignal(str)  # must be declared at class level for PyQt6

    def __init__(self, framework, module_name, module_instance, parent=None):
        super().__init__(parent)
        self.framework = framework
        self.module_name = module_name
        self.module_instance = module_instance
        self.module_runner = None
        self.option_widgets = {}
        # 3. Hubungkan SEBELUM _build_ui, paksa QueuedConnection
        self._safe_append.connect(self._do_append, Qt.ConnectionType.QueuedConnection)

        self._build_ui()

    def _build_ui(self):
        # === VSCode Minimal Dark palette ===
        # bg:       #1e1e1e   editor background
        # surface:  #252526   sidebar / header
        # border:   #3c3c3c   subtle dividers
        # text:     #cccccc   default text
        # muted:    #858585   dimmed labels
        # accent:   #007acc   VSCode blue (active tab / run btn)
        # danger:   #c72e2e   stop / close

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── HEADER BAR ─────────────────────────────────────────
        header_widget = QWidget()
        header_widget.setFixedHeight(40)
        header_widget.setStyleSheet("""
            QWidget {
                background: #252526;
                border-bottom: 1px solid #3c3c3c;
            }
        """)
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(12, 0, 8, 0)
        header_layout.setSpacing(6)

        module_short_name = self.module_name.split('/')[-1]
        title = QLabel(module_short_name)
        title.setStyleSheet("""
            color: #cccccc;
            font-size: 10pt;
            font-weight: bold;
            background: transparent;
            border: none;
        """)
        header_layout.addWidget(title)
        header_layout.addStretch()

        BTN_W, BTN_H = 80, 26

        # ── Run / Stop ──
        self.run_btn = QPushButton("▶ Run")
        self.run_btn.setProperty("action", "run")
        self.run_btn.setFixedSize(BTN_W, BTN_H)
        self.run_btn.clicked.connect(self._handle_run_stop)
        self.run_btn.setStyleSheet("""
            QPushButton {
                background: #007acc;
                color: #ffffff;
                border: none;
                border-radius: 0;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover { background: #1a8cdb; }
            QPushButton:pressed { background: #005a9e; }
            QPushButton[action="stop"] { background: #c72e2e; }
            QPushButton[action="stop"]:hover { background: #e03333; }
        """)
        header_layout.addWidget(self.run_btn)

        # ── Clear ──
        clear_btn = QPushButton("Clear")
        clear_btn.setFixedSize(BTN_W, BTN_H)
        clear_btn.setStyleSheet("""
            QPushButton {
                background: #2d2d2d;
                color: #cccccc;
                border: 1px solid #3c3c3c;
                border-radius: 0;
                font-size: 10px;
            }
            QPushButton:hover { background: #3a3a3a; }
            QPushButton:pressed { background: #444; }
        """)
        header_layout.addWidget(clear_btn)

        # ── Close ──
        close_btn = QPushButton("✕")
        close_btn.setFixedSize(32, BTN_H)
        close_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #858585;
                border: none;
                border-radius: 0;
                font-size: 12px;
            }
            QPushButton:hover {
                background: #c72e2e;
                color: #ffffff;
            }
        """)
        close_btn.clicked.connect(self._request_close)
        header_layout.addWidget(close_btn)

        layout.addWidget(header_widget)

        # ── INNER TABS ─────────────────────────────────────────
        inner_tabs = QTabWidget()
        inner_tabs.setDocumentMode(True)
        inner_tabs.setMinimumHeight(380)
        inner_tabs.setStyleSheet("""
            QTabWidget {
                border: none;
            }
            QTabWidget::pane {
                border: none;
                border-top: 1px solid #3c3c3c;
                background: #1e1e1e;
            }
            QTabBar {
                background: #252526;
            }
            QTabBar::tab {
                background: #252526;
                color: #858585;
                padding: 6px 16px;
                margin: 0;
                font-size: 10px;
                border: none;
                border-bottom: 2px solid transparent;
            }
            QTabBar::tab:selected {
                color: #cccccc;
                border-bottom: 2px solid #007acc;
                background: #1e1e1e;
            }
            QTabBar::tab:hover:!selected {
                color: #cccccc;
                background: #2a2d2e;
            }
        """)

        # ── Tab: Options ──
        options_widget = QWidget()
        self.options_layout = QFormLayout(options_widget)
        self.options_layout.setSpacing(8)
        self.options_layout.setContentsMargins(10, 10, 10, 10)
        

        options_scroll = QScrollArea()
        options_scroll.setWidgetResizable(True)
        options_scroll.setFrameShape(QFrame.Shape.NoFrame)
        options_scroll.setWidget(options_widget)
        options_scroll.setStyleSheet("""
            QScrollArea { border: none; background: #1e1e1e; }
            QScrollBar:vertical {
                background: #1e1e1e;
                width: 8px;
            }
            QScrollBar::handle:vertical {
                background: #424242;
                min-height: 24px;
            }
            QScrollBar::handle:vertical:hover { background: #686868; }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical { height: 0; }
        """)
        inner_tabs.addTab(options_scroll, "Options")

        # ── Tab: Console ──
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("DejaVu Sans Mono", 9))
        self.console.setStyleSheet("""
            QTextEdit {
                background: #1e1e1e;
                color: #d4d4d4;
                border: none;
                padding: 8px;
                selection-background-color: #264f78;
            }
        """)
        inner_tabs.addTab(self.console, "Console")

        # ── Tab: Info ──
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setFont(QFont("Hack", 9))
        self.info_text.setStyleSheet("""
            QTextEdit {
                background: #1e1e1e;
                color: #d4d4d4;
                border: none;
                padding: 8px;
            }
        """)
        inner_tabs.addTab(self.info_text, "Info")

        layout.addWidget(inner_tabs, 1)

        # ── Sambungkan Clear ke tab console yang sudah dibuat ──
        clear_btn.clicked.connect(self.console.clear)

        self._load_module_info()
    
    

    def _load_module_info(self):
        """Load module info - SAMA PERSIS dengan gui.py"""
        try:
            import contextlib
            import io
            
            # Capture info output dari framework
            output_buffer = io.StringIO()
            
            # Backup current module
            old_module = self.framework.loaded_module
            
            # Temporarily set this module as loaded
            self.framework.loaded_module = self.module_instance
            
            # Run info command
            with contextlib.redirect_stdout(output_buffer), contextlib.redirect_stderr(output_buffer):
                self.framework.cmd_info([])
            
            # Restore old module
            self.framework.loaded_module = old_module
            
            # Get the output
            info_output = output_buffer.getvalue()
            
            # Tampilkan dengan format yang sama seperti gui.py
            if info_output.strip():
                html_output = self.create_module_info_html(info_output)
                self.info_text.setHtml(html_output)
            else:
                self.info_text.setPlainText("No module info available")
                
        except Exception as e:
            self.info_text.setPlainText(f"Error loading module info: {e}")

    def create_module_info_html(self, text):
        """Create module info HTML - SAMA PERSIS dengan gui.py"""
        import re
        
        # Bersihkan ANSI sequences
        clean_text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        
        # Tambahkan warna untuk informasi penting
        colored_text = self.add_rank_colors(clean_text)
        
        # HTML dengan styling (sama seperti gui.py)
        html = f"""
        <html>
        <head>
        <style>
            body {{
                font-family: 'Fira Code', 'DejaVu Sans Mono', monospace;
                font-weight: bold;
                font-size: 11px;
                background: #000;
                color: #ffffff;
                margin: 0;
                padding: 10px;
                line-height: 1.3;
            }}
            .module-header {{
                color: #00ffff;
                font-weight: bold;
                font-size: 13px;
                margin-bottom: 10px;
                border-bottom: 1px solid #00ffff;
                padding-bottom: 5px;
            }}
            .section {{
                margin: 8px 0;
                padding: 8px;
                background: #252525;
                border: 1px solid #404040;
                border-radius: 3px;
            }}
            .option-table {{
                width: 100%;
                border-collapse: collapse;
                margin: 5px 0;
                font-size: 10px;
            }}
            .option-table th {{
                background: #2d2d2d;
                color: #ff79c6;
                padding: 4px 6px;
                text-align: left;
                border: 1px solid #404040;
            }}
            .option-table td {{
                padding: 4px 6px;
                border: 1px solid #404040;
                color: #d4d4d4;
            }}
            .rank-excellent {{ color: #ff5555; font-weight: bold; }}
            .rank-great {{ color: #ff79c6; font-weight: bold; }}
            .rank-good {{ color: #f1fa8c; font-weight: bold; }}
            .rank-normal {{ color: #50fa7b; font-weight: bold; }}
            .rank-average {{ color: #8be9fd; font-weight: bold; }}
            .rank-low {{ color: #bd93f9; font-weight: bold; }}
            .rank-manual {{ color: #ffb86c; font-weight: bold; }}
            .info-name {{ color: #8be9fd; font-weight: bold; }}
            .info-module {{ color: #ff79c6; }}
            .info-type {{ color: #50fa7b; }}
            .info-platform {{ color: #f1fa8c; }}
            .info-arch {{ color: #bd93f9; }}
            .info-author {{ color: #ffb86c; }}
            .info-license {{ color: #ff5555; }}
            pre {{
                font-family: 'DejaVu Sans Mono', 'Courier New', monospace;
                white-space: pre-wrap;
                margin: 0;
                color: #d4d4d4;
            }}
        </style>
        </head>
        <body>
            <div class="module-header">LAZYFRAMEWORK MODULE INFORMATION</div>
            <pre>{colored_text}</pre>
        </body>
        </html>
        """
        return html

    def add_rank_colors(self, text):
        """Tambahkan warna untuk rank - SAMA PERSIS dengan gui.py"""
        lines = text.split('\n')
        colored_lines = []
        
        for line in lines:
            colored_line = line
            
            # Warna untuk Rank
            if 'Rank:' in line:
                if 'Excellent' in line:
                    colored_line = line.replace('Excellent', '<span class="rank-excellent">Excellent</span>')
                elif 'Great' in line:
                    colored_line = line.replace('Great', '<span class="rank-great">Great</span>')
                elif 'Good' in line:
                    colored_line = line.replace('Good', '<span class="rank-good">Good</span>')
                elif 'Normal' in line:
                    colored_line = line.replace('Normal', '<span class="rank-normal">Normal</span>')
                elif 'Average' in line:
                    colored_line = line.replace('Average', '<span class="rank-average">Average</span>')
                elif 'Low' in line:
                    colored_line = line.replace('Low', '<span class="rank-low">Low</span>')
                elif 'Manual' in line:
                    colored_line = line.replace('Manual', '<span class="rank-manual">Manual</span>')
            
            # Warna untuk informasi module lainnya
            elif 'Name:' in line:
                colored_line = line.replace('Name:', '<span class="info-name">Name:</span>')
            elif 'Module:' in line:
                colored_line = line.replace('Module:', '<span class="info-module">Module:</span>')
            elif 'Type:' in line:
                colored_line = line.replace('Type:', '<span class="info-type">Type:</span>')
            elif 'Platform:' in line:
                colored_line = line.replace('Platform:', '<span class="info-platform">Platform:</span>')
            elif 'Arch:' in line:
                colored_line = line.replace('Arch:', '<span class="info-arch">Arch:</span>')
            elif 'Author:' in line:
                colored_line = line.replace('Author:', '<span class="info-author">Author:</span>')
            elif 'License:' in line:
                colored_line = line.replace('License:', '<span class="info-license">License:</span>')
            
            # Warna untuk section headers
            elif 'Module options' in line or 'Module parameters' in line:
                colored_line = f'<span style="color: #ff5555; font-weight: bold;">{line}</span>'
            elif 'Description:' in line:
                colored_line = f'<span style="color: #50fa7b; font-weight: bold;">{line}</span>'
            
            colored_lines.append(colored_line)
        
        return '\n'.join(colored_lines)

    # ── Output ──────────────────────────────────────────────
   # 4. Ini yang dipanggil dari luar (aman dari thread manapun)
    def append_output(self, text: str):
        self._safe_append.emit(text)

    # 5. Ini yang benar-benar menyentuh QTextEdit (selalu jalan di main thread)
    def _do_append(self, text: str):
        if not text or not text.strip():
            return

        html_output = self.rich_to_html_with_matrix(text)
        self.console.insertHtml(html_output + "<br>")

        cursor = self.console.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.console.setTextCursor(cursor)

    def rich_to_html_with_matrix(self, text: str):
        """Convert rich/ANSI/nmap text to colored HTML - full version"""
        import re

        COLOR = {
            'black': '#000000', 'red': '#ff5555', 'green': '#00ff00',
            'yellow': '#ffff00', 'blue': '#5555ff', 'magenta': '#ff00ff',
            'cyan': '#00ffff', 'white': '#ffffff', 'orange': '#ffaa00',
            'bright_green': '#88ff88', 'bright_cyan': '#88ffff',
            'dim': '#558855', 'success': '#00ff00', 'error': '#ff5555',
            'warning': '#ffff00', 'info': '#00ffff', 'session': '#ffaa00',
            'matrix_green': '#00ff00', 'matrix_cyan': '#00ffff',
            'hacker_green': '#00ff00', 'neon_blue': '#5555ff',
            'debug': '#ff00ff',
        }
        ANSI = {
            '0': 'reset', '1': 'bold', '2': 'dim',
            '30': 'black',  '31': 'red',    '32': 'green',   '33': 'yellow',
            '34': 'blue',   '35': 'magenta','36': 'cyan',    '37': 'white',
            '90': 'black',  '91': 'red',    '92': 'bright_green', '93': 'yellow',
            '94': 'blue',   '95': 'magenta','96': 'bright_cyan',  '97': 'white',
        }
        # All box-drawing chars including rounded corners and heavy lines
        BOX_CHARS = '│─┌┐└┘├┤┬┴┼╭╮╯╰━'

        # 1. Strip OSC / misc escape sequences
        text = re.sub(r'\x1b\][^\x07\x1b]*\x07', '', text)
        text = re.sub(r'\x1b[=><]', '', text)

        # 2. ANSI codes (with or without ESC prefix) → Rich-style tags
        def ansi_to_rich(m):
            out = ''
            for c in m.group(1).split(';'):
                if c in ('', '0'): out += '[/]'
                elif c == '1':   out += '[bold]'
                elif c in ANSI:  out += f'[{ANSI[c]}]'
            return out
        text = re.sub(r'(?:\x1b)?\[([0-9;]+)[mG]', ansi_to_rich, text)
        text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        text = text.replace('\x1b', '')

        # 3. HTML-escape special chars
        text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

        # 4. Nmap keyword coloring per line
        def color_nmap_line(line):
            line = re.sub(r'\b(open)\b',
                r'<span style="color:#00ff00;font-weight:bold;text-shadow:0 0 6px #00ff00">\1</span>', line)
            line = re.sub(r'\b(closed)\b',
                r'<span style="color:#ff5555;opacity:0.7">\1</span>', line)
            line = re.sub(r'\b(filtered)\b',
                r'<span style="color:#ffff00;font-weight:bold">\1</span>', line)
            line = re.sub(r'(\d+/(?:tcp|udp))',
                r'<span style="color:#00ffff">\1</span>', line)
            line = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d+)?)',
                r'<span style="color:#88ffff">\1</span>', line)
            return line

        lines = text.split('\n')
        lines = [color_nmap_line(l) for l in lines]
        text = '\n'.join(lines)

        # 5. Process Rich-style tags [color]...[/]
        stack = []
        out = ''
        i = 0
        while i < len(text):
            if text[i] == '[':
                end_pos = text.find(']', i)
                if end_pos != -1:
                    tag = text[i+1:end_pos]
                    if tag == '/':
                        if stack: stack.pop()
                        out += '</span>'
                        i = end_pos + 1; continue
                    if tag in COLOR:
                        stack.append(tag)
                        c = COLOR[tag]
                        glow = f'text-shadow:0 0 6px {c};'
                        out += f'<span style="color:{c};{glow}font-weight:bold">'
                        i = end_pos + 1; continue
                    if tag == 'bold':
                        stack.append('bold')
                        out += '<span style="color:#00ff00;font-weight:bold">'
                        i = end_pos + 1; continue
                    if tag == 'dim':
                        stack.append('dim')
                        out += '<span style="color:#558855">'
                        i = end_pos + 1; continue
                    if tag.lower() in ('underline', 'u'):
                        stack.append('underline')
                        out += '<span style="text-decoration:underline;color:#00ffff">'
                        i = end_pos + 1; continue
            out += text[i]; i += 1
        while stack:
            stack.pop(); out += '</span>'

        # 6. Box-drawing chars (standard + rounded + heavy)
        for ch in BOX_CHARS:
            out = out.replace(ch, f'<span style="color:#00ff00;text-shadow:0 0 4px #00ff00">{ch}</span>')

        # 7. Newlines → <br>
        out = out.replace('\n', '<br>')

        return (
            f'<span style="font-family:\'Courier New\',monospace;'
            f'color:#00ff00;white-space:pre-wrap;word-wrap:break-word;line-height:1.5">'
            f'{out}</span>'
        )


    def format_unicode_table(self, text: str):
        """Format unicode table dengan Matrix theme - SAMA PERSIS dengan gui.py"""
        # Escape HTML
        safe = (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
        )
        
        lines = safe.split("\n")
        if not lines:
            return ""
        
        max_len = max(len(line) for line in lines)
        normalized = []
        
        for line in lines:
            if len(line) < max_len:
                line = line + (" " * (max_len - len(line)))
            elif len(line) > max_len:
                line = line[:max_len]
            normalized.append(line)
        
        styled_lines = [self.style_matrix_table_line(line) for line in normalized]
        styled_text = "<br>".join(styled_lines)
        
        html = f"""
        <div style="
            width: max-content;
            max-width: 100%;
            overflow-x: auto;
            padding: 8px;
            margin: 5px 0;
            background: rgba(0, 255, 0, 0.05);
            border: 1px solid #008800;
            border-radius: 3px;
            box-shadow: 0 0 10px rgba(0, 255, 0, 0.2);
        ">
            <pre style="
                font-family: 'Courier New', monospace;
                font-size: 11px;
                white-space: pre;
                margin: 0;
                color: #00ff00;
                text-shadow: 0 0 3px rgba(0, 255, 0, 0.5);
            ">{styled_text}</pre>
        </div>
        """
        return html
    
    
    def style_matrix_table_line(self, line: str):
        """Style table line dengan Matrix theme"""
        border_chars = ['─', '│', '┌', '┐', '└', '┘', '┬', '┴', '├', '┤', '┼']
        
        if all(char in border_chars + [' '] for char in line):
            return f'<span style="color: #00ff00; text-shadow: 0 0 5px #00ff00;">{line}</span>'
        
        result = []
        for char in line:
            if char in border_chars:
                result.append(f'<span style="color: #00ff00; text-shadow: 0 0 5px #00ff00;">{char}</span>')
            elif char.isdigit():
                result.append(f'<span style="color: #ffaa00;">{char}</span>')
            elif char.isalpha():
                result.append(f'<span style="color: #88ff88;">{char}</span>')
            else:
                result.append(f'<span style="color: #00ff00;">{char}</span>')
        
        return ''.join(result)


    # ── Run / Stop ───────────────────────────────────────────
    def _handle_run_stop(self):
        if self.run_btn.property("action") == "run":
            self._start()
        else:
            self._stop()

    def _start(self):
        if self.module_runner and self.module_runner.isRunning():
            return

        self.module_runner = ModuleRunner(self.framework, self.module_instance)
        self.module_runner.output.connect(
        self.append_output,
        Qt.ConnectionType.QueuedConnection
        )
        self.module_runner.finished.connect(self._on_finished)
        self.module_runner.start()

        self.run_btn.setText("STOP")
        self.run_btn.setProperty("action", "stop")
        self.append_output(f"[green]▶ Starting {self.module_name}...[/]")

    def _stop(self):
        if self.module_runner and self.module_runner.isRunning():
            self.module_runner.stop()
        self.append_output(f"[yellow]■ Stopping {self.module_name}...[/]")

    def _on_finished(self):
        self.run_btn.setText("START")
        self.run_btn.setProperty("action", "run")
        self.append_output(f"[cyan]✓ {self.module_name} finished.[/]")

    # ── Close ────────────────────────────────────────────────
    def _request_close(self):
        """Request to close this tab"""
        try:
            self._stop()  # Stop dulu jika sedang running
            
            # Cari parent QTabWidget
            parent = self.parent()
            while parent is not None:
                if isinstance(parent, QTabWidget):
                    idx = parent.indexOf(self)
                    if idx >= 0:
                        parent.removeTab(idx)
                        self.deleteLater()
                        return
                parent = parent.parent()
            
            # Fallback jika tidak ketemu
            if self.parent():
                self.parent().layout().removeWidget(self)
            self.deleteLater()
            
        except Exception as e:
            print(f"[ERROR] Close tab error: {e}")
            # Force delete
            self.deleteLater()