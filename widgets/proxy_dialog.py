from PyQt6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox, QLineEdit, QComboBox, QPushButton, QMessageBox
from PyQt6.QtGui import QIntValidator

# === PROXY SETTINGS DIALOG - TANPA BROWSE FILE ===
class ProxySettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setWindowTitle("Proxy Settings")
        self.setModal(True)
        self.setFixedSize(400, 300)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # HAPUS BAGIAN PROXY LIST DARI FILE
        # Langsung ke Manual Proxy Input saja

        # Manual Proxy Input (sederhana)
        manual_group = QGroupBox("Manual Proxy Configuration")
        manual_layout = QFormLayout()
        
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("127.0.0.1 or proxy.com")
        manual_layout.addRow("Host:", self.host_input)
        
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("8080")
        self.port_input.setValidator(QIntValidator(1, 65535))
        manual_layout.addRow("Port:", self.port_input)
        
        self.type_combo = QComboBox()
        self.type_combo.addItems(["HTTP", "SOCKS5", "SOCKS4"])
        manual_layout.addRow("Type:", self.type_combo)
        
        manual_group.setLayout(manual_layout)
        layout.addWidget(manual_group)

        # Quick Tor button
        tor_group = QGroupBox("Quick Setup")
        tor_layout = QHBoxLayout()
        
        tor_btn = QPushButton("Use Tor Proxy (127.0.0.1:9050)")
        tor_btn.clicked.connect(self.set_tor_proxy)
        tor_layout.addWidget(tor_btn)
        
        tor_group.setLayout(tor_layout)
        layout.addWidget(tor_group)

        # Action Buttons
        btn_layout = QHBoxLayout()
        
        test_btn = QPushButton("Test")
        test_btn.clicked.connect(self.test_proxy)
        btn_layout.addWidget(test_btn)
        
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self.apply_proxy)
        apply_btn.setDefault(True)
        btn_layout.addWidget(apply_btn)
        
        disable_btn = QPushButton("Disable")
        disable_btn.clicked.connect(self.disable_proxy)
        btn_layout.addWidget(disable_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.load_current_settings()

    def set_tor_proxy(self):
        """Set Tor proxy settings"""
        self.host_input.setText("127.0.0.1")
        self.port_input.setText("9050")
        self.type_combo.setCurrentText("SOCKS5")

    def load_current_settings(self):
        """Load current proxy settings"""
        if self.parent.current_proxy:
            self.host_input.setText(self.parent.current_proxy.get('server', ''))
            self.port_input.setText(str(self.parent.current_proxy.get('port', '')))
            self.type_combo.setCurrentText(self.parent.current_proxy.get('type', 'HTTP').upper())

    def test_proxy(self):
        """Test proxy connection"""
        proxy_config = self.get_proxy_config()
        if proxy_config:
            self.parent.test_proxy_connection(proxy_config)

    def apply_proxy(self):
        """Apply proxy settings"""
        proxy_config = self.get_proxy_config()
        if proxy_config:
            # Tentukan proxy mode berdasarkan type
            if proxy_config['type'] == 'socks5' and proxy_config['server'] == '127.0.0.1' and proxy_config['port'] == 9050:
                self.parent.framework.session["proxy_mode"] = "Tor"
            else:
                self.parent.framework.session["proxy_mode"] = "Manual"
            
            self.parent.set_proxy(proxy_config)
            self.parent.enable_proxy()
            self.accept()

    def disable_proxy(self):
        """Disable proxy"""
        self.parent.disable_proxy()
        self.accept()

    def get_proxy_config(self):
        """Get proxy configuration from inputs"""
        host = self.host_input.text().strip()
        port = self.port_input.text().strip()
        proxy_type = self.type_combo.currentText().lower()

        if not host or not port:
            QMessageBox.warning(self, "Error", "Please enter host and port")
            return None

        try:
            port_int = int(port)
        except ValueError:
            QMessageBox.warning(self, "Error", "Please enter a valid port number")
            return None

        return {
            'type': proxy_type,
            'server': host,
            'port': port_int,
            'username': '',
            'password': ''
        }