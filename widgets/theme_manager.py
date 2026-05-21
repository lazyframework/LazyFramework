import os
import json
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QComboBox

class ThemeManager:
    def __init__(self, app, main_window):
        self.app = app
        self.main_window = main_window
        
        # PATH YANG BENAR: themes ada di DALAM folder widgets
        current_dir = os.path.dirname(os.path.abspath(__file__))  # ini folder widgets/
        self.theme_path = os.path.join(current_dir, "themes")    # widgets/themes/
        
        # Buat folder themes jika belum ada
        os.makedirs(self.theme_path, exist_ok=True)
        
        # Scan themes dari folder
        self.theme_map = self._scan_themes()
        print(f"[*] Themes detected: {list(self.theme_map.keys())}")
        print(f"[*] Theme path: {self.theme_path}")
        
        # Load dari config
        self.current_theme = self._load_from_config()
        if self.current_theme:
            self.load_theme(self.current_theme)

    def _scan_themes(self):
        """Scan semua file .qss di folder themes"""
        themes = {}
        if os.path.exists(self.theme_path):
            for file in os.listdir(self.theme_path):
                if file.endswith('.qss'):
                    # Nama display: hapus .qss, replace _ dengan space, capitalize
                    display_name = file.replace('.qss', '').replace('_', ' ').title()
                    themes[display_name] = file
                    print(f"  Found: {display_name} -> {file}")
        else:
            print(f"[!] Theme folder not found: {self.theme_path}")
        return themes

    def _load_from_config(self):
        """Load theme dari config.json"""
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")
        
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
                    saved = config.get("theme", "")
                    if saved and any(saved == v for v in self.theme_map.values()):
                        return saved
            except:
                pass
        
        # Default ke theme pertama yang ditemukan
        if self.theme_map:
            return list(self.theme_map.values())[0]
        return None

    def _save_to_config(self, theme_filename):
        """Save theme ke config.json"""
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")
        
        try:
            config = {}
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
            
            config["theme"] = theme_filename
            
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
        except:
            pass

    def load_theme(self, theme_filename):
        """Load theme dari file .qss"""
        if not theme_filename:
            return
            
        theme_path = os.path.join(self.theme_path, theme_filename)
        
        if not os.path.exists(theme_path):
            print(f"[!] Theme file not found: {theme_path}")
            return
        
        try:
            with open(theme_path, "r", encoding="utf-8") as f:
                stylesheet = f.read()
            
            self.app.setStyleSheet(stylesheet)
            self.current_theme = theme_filename
            self._save_to_config(theme_filename)
            print(f"[+] Theme loaded: {theme_filename}")
            
            # Update session info di main window jika ada methodnya
            if hasattr(self.main_window, 'update_session_info'):
                self.main_window.update_session_info()
                
        except Exception as e:
            print(f"[-] Failed to load theme {theme_filename}: {e}")

    def get_available_themes(self):
        """Return list of available theme display names"""
        return list(self.theme_map.keys())

    def create_theme_switcher(self):
        """Buat widget dropdown untuk memilih theme"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(8)

        label = QLabel("Mode:")
        label.setStyleSheet("color: #fff; font-weight: bold; font-size: 11pt;")

        combo = QComboBox()
        combo.setMinimumWidth(140)
        
        # Isi dropdown dengan themes yang ada di folder
        for display_name in self.theme_map.keys():
            combo.addItem(display_name)
        
        # Set current selection
        current_display = None
        for display_name, filename in self.theme_map.items():
            if filename == self.current_theme:
                current_display = display_name
                break
        
        if current_display:
            combo.setCurrentText(current_display)
        
        # Connect event
        combo.currentTextChanged.connect(self._on_theme_changed)
        
        # Style untuk dropdown
        combo.setStyleSheet("""
            QComboBox {
                background-color: #080807;
                color: #fff;
                border: 1px solid #827f7f;
                padding: 5px 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            QComboBox:hover {
                border: 1px solid #ff5252;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox QAbstractItemView {
                background-color: #080807;
                color: #ff5252;
                selection-background-color: #fcfafa;
                selection-color: white;
                border: 1px solid #c62828;
            }
        """)
        
        layout.addWidget(label)
        layout.addWidget(combo)
        layout.addStretch()
        
        return widget

    def _on_theme_changed(self, display_name):
        """Handler ketika theme berubah dari dropdown"""
        if display_name in self.theme_map:
            self.load_theme(self.theme_map[display_name])