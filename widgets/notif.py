from PyQt6.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QApplication, QGraphicsDropShadowEffect
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QRectF
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QLinearGradient, QPainterPath
import time

# ── Toast stack manager ───────────────────────────────────────────────────────
_ACTIVE_TOASTS: list = []
_TOAST_HEIGHT   = 85
_TOAST_GAP      = 8
_TOAST_MARGIN_R = 20
_TOAST_MARGIN_B = 50


def _restack():
    """Susun ulang posisi semua toast yang aktif dari bawah ke atas."""
    screen = QApplication.primaryScreen().availableGeometry()
    for i, t in enumerate(_ACTIVE_TOASTS):
        target_y = screen.height() - _TOAST_MARGIN_B - (i + 1) * (_TOAST_HEIGHT + _TOAST_GAP)
        target_x = screen.width() - t.width() - _TOAST_MARGIN_R
        t.move(target_x, target_y)


# ── Warna per level ───────────────────────────────────────────────────────────
_LEVEL_COLORS = {
    "info":    QColor(0,   180, 220),
    "success": QColor(50,  200, 70),
    "warning": QColor(220, 160, 0),
    "error":   QColor(220, 50,  70),
}

_LEVEL_ICONS = {
    "info":    "●",
    "success": "✓",
    "warning": "▲",
    "error":   "✕",
}


class CyberpunkToast(QWidget):
    """Toast notifikasi minimalis - clean & modern"""

    def __init__(self, parent=None, title="", message="",
                 duration=4500, level="info", width=350, icon=None):
        super().__init__(parent, Qt.WindowType.FramelessWindowHint |
                                 Qt.WindowType.WindowStaysOnTopHint |
                                 Qt.WindowType.Tool)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        self.duration = duration
        self.level = level.lower() if level.lower() in _LEVEL_COLORS else "info"
        self.accent = _LEVEL_COLORS[self.level]
        self._width = width

        self._build_ui(title, message, icon)
        self._build_shadow()

        # Auto dismiss
        QTimer.singleShot(self.duration, self._slide_out)

        _ACTIVE_TOASTS.append(self)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self, title, message, icon):
        self.setFixedWidth(self._width)
        self.setMinimumHeight(70)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 14, 12)
        root.setSpacing(6)

        # ── baris judul ──────────────────────────────────────────────────────
        top = QHBoxLayout()
        top.setSpacing(8)

        # icon
        lbl_icon = QLabel(icon or _LEVEL_ICONS[self.level])
        lbl_icon.setFixedSize(20, 20)
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_icon.setStyleSheet(f"""
            QLabel {{
                color: {self.accent.name()};
                font-size: 12px;
                font-weight: bold;
                background-color: rgba({self.accent.red()}, {self.accent.green()}, {self.accent.blue()}, 0.15);
                border-radius: 10px;
            }}
        """)
        top.addWidget(lbl_icon)

        # title
        lbl_title = QLabel((title or "LAZYFRAMEWORK").upper())
        lbl_title.setFont(self._mono(10, bold=True))
        lbl_title.setStyleSheet(f"color: {self.accent.name()};")
        top.addWidget(lbl_title)
        top.addStretch()

        # close button
        btn_close = QLabel("✕")
        btn_close.setFixedSize(18, 18)
        btn_close.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn_close.setStyleSheet("""
            QLabel {
                color: #888;
                font-size: 10px;
                border-radius: 9px;
                background: rgba(255,255,255,0.05);
            }
            QLabel:hover {
                color: #fff;
                background: rgba(255,255,255,0.15);
            }
        """)
        btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_close.mousePressEvent = lambda _: self._slide_out()
        top.addWidget(btn_close)

        root.addLayout(top)

        # ── pesan ─────────────────────────────────────────────────────────────
        lbl_msg = QLabel(message)
        lbl_msg.setFont(self._mono(9))
        lbl_msg.setWordWrap(True)
        lbl_msg.setStyleSheet("color: #bbbbbb; padding-left: 28px;")
        root.addWidget(lbl_msg)

        # ── progress bar ──────────────────────────────────────────────────────
        self._bar = QWidget()
        self._bar.setFixedHeight(2)
        self._bar.setFixedWidth(self._width - 32)
        self._bar.setStyleSheet(f"background-color: {self.accent.name()}; border-radius: 1px;")
        root.addWidget(self._bar)

        # animasi bar
        self._bar_anim = QPropertyAnimation(self._bar, b"minimumWidth", self)
        self._bar_anim.setDuration(self.duration - 300)
        self._bar_anim.setStartValue(self._width - 32)
        self._bar_anim.setEndValue(0)
        self._bar_anim.setEasingCurve(QEasingCurve.Type.Linear)

        self.adjustSize()

    def _build_shadow(self):
        sh = QGraphicsDropShadowEffect(self)
        sh.setBlurRadius(20)
        sh.setOffset(0, 3)
        sh.setColor(QColor(0, 0, 0, 100))
        self.setGraphicsEffect(sh)

    @staticmethod
    def _mono(size: int, bold=False) -> QFont:
        f = QFont("Consolas, DejaVu Sans Mono, Courier New, monospace")
        f.setStyleHint(QFont.StyleHint.Monospace)
        f.setPointSize(size)
        if bold:
            f.setWeight(QFont.Weight.Bold)
        return f

    # ── animasi ───────────────────────────────────────────────────────────────

    def showEvent(self, event):
        super().showEvent(event)
        screen = QApplication.primaryScreen().availableGeometry()
        end_x = screen.width() - self._width - _TOAST_MARGIN_R
        end_y = screen.height() - _TOAST_MARGIN_B - _TOAST_HEIGHT

        self.move(screen.width() + 40, end_y)

        self._slide_in = QPropertyAnimation(self, b"pos", self)
        self._slide_in.setDuration(350)
        self._slide_in.setStartValue(QPoint(screen.width() + 40, end_y))
        self._slide_in.setEndValue(QPoint(end_x, end_y))
        self._slide_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._slide_in.finished.connect(_restack)
        self._slide_in.start()

        self._bar_anim.start()

    def _slide_out(self):
        self._bar_anim.stop()

        screen = QApplication.primaryScreen().availableGeometry()
        out_x = screen.width() + 40

        anim = QPropertyAnimation(self, b"pos", self)
        anim.setDuration(280)
        anim.setStartValue(self.pos())
        anim.setEndValue(QPoint(out_x, self.pos().y()))
        anim.setEasingCurve(QEasingCurve.Type.InCubic)
        anim.finished.connect(self.close)
        anim.start()

    # ── paint ─────────────────────────────────────────────────────────────────

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Convert to int untuk menghindari TypeError
        w = int(self.width())
        h = int(self.height())
        
        r = QRectF(1, 1, w - 2, h - 2)

        # Background gelap
        bg = QLinearGradient(0, 0, 0, h)
        bg.setColorAt(0, QColor(28, 28, 32, 245))
        bg.setColorAt(1, QColor(20, 20, 24, 245))
        
        path = QPainterPath()
        path.addRoundedRect(r, 8, 8)
        p.fillPath(path, bg)

        # Border tipis
        border = QColor(self.accent)
        border.setAlpha(100)
        p.setPen(QPen(border, 1))
        p.drawRoundedRect(r, 8, 8)

        # Garis accent kiri - menggunakan integer
        p.setPen(QPen(self.accent, 3))
        p.drawLine(2, 10, 2, h - 10)

    def closeEvent(self, event):
        if self in _ACTIVE_TOASTS:
            _ACTIVE_TOASTS.remove(self)
        _restack()
        super().closeEvent(event)