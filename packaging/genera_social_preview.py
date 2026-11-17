"""Genera docs/social-preview.png (1280x640, anteprima del repository su GitHub) da icona e screenshot.
Uso:  python packaging/genera_social_preview.py        (richiede PyQt6; su Windows usa i font di sistema)"""
import os
import re
import sys

QUI = os.path.dirname(os.path.abspath(__file__))
RADICE = os.path.dirname(QUI)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if sys.platform == "win32":
    os.environ.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")

from PyQt6.QtCore import QByteArray, QPointF, QRectF, Qt          # noqa: E402
from PyQt6.QtGui import (QBrush, QColor, QFont, QGuiApplication, QImage, QLinearGradient, QPainter,  # noqa: E402
                         QPainterPath, QPen, QRadialGradient)
from PyQt6.QtSvg import QSvgRenderer                               # noqa: E402

L, H = 1280, 640
SFONDO, TESTO, ATTENUATO, ACCENTO, VERDE = "#13141B", "#E8E9F0", "#B4B7CA", "#A9B5FF", "#5CD3A0"


def font(px, peso=QFont.Weight.Normal):
    f = QFont("Segoe UI")
    f.setPixelSize(px)
    f.setWeight(peso)
    return f


def testo_ricco(p, x, y, pezzi, px):
    """Una riga di testo con pezzi normali e in grassetto: [(testo, grassetto, colore)]."""
    for t, grassetto, colore in pezzi:
        p.setFont(font(px, QFont.Weight.DemiBold if grassetto else QFont.Weight.Normal))
        p.setPen(QColor(colore))
        p.drawText(QPointF(x, y), t)
        x += p.fontMetrics().horizontalAdvance(t)


def main():
    app = QGuiApplication(sys.argv)
    versione = re.search(r'APP_VERSION = "([^"]+)"', open(os.path.join(RADICE, "P7MReader.py"), encoding="utf-8").read()).group(1)
    svg = re.search(r'ICON_SVG = """(.*?)"""', open(os.path.join(RADICE, "P7MReader.py"), encoding="utf-8").read(), re.S).group(1)
    img = QImage(L, H, QImage.Format.Format_ARGB32)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)

    # sfondo: sfumatura, griglia leggera, aloni di colore
    g = QLinearGradient(0, 0, L, H)
    g.setColorAt(0, QColor("#15161F"))
    g.setColorAt(1, QColor("#0F1016"))
    p.fillRect(img.rect(), g)
    p.setPen(QPen(QColor(255, 255, 255, 9), 1))
    for x in range(0, L, 32):
        p.drawLine(x, 0, x, H)
    for y in range(0, H, 32):
        p.drawLine(0, y, L, y)
    for cx, cy, r, col in ((130, 190, 260, QColor(142, 157, 255, 48)), (40, 640, 360, QColor(92, 211, 160, 26))):
        rg = QRadialGradient(cx, cy, r)
        rg.setColorAt(0, col)
        rg.setColorAt(1, QColor(0, 0, 0, 0))
        p.fillRect(img.rect(), QBrush(rg))

    # screenshot a destra, come una finestra appoggiata e tagliata dal bordo
    shot = QImage(os.path.join(RADICE, "docs", "screenshot.png"))
    finestra = QRectF(690, 88, 820, 820 * shot.height() / shot.width())
    ombra = QPainterPath()
    ombra.addRoundedRect(finestra.adjusted(-6, -6, 6, 6), 18, 18)
    p.fillPath(ombra, QColor(0, 0, 0, 120))
    clip = QPainterPath()
    clip.addRoundedRect(finestra, 14, 14)
    p.save()
    p.setClipPath(clip)
    p.drawImage(finestra, shot)
    p.restore()
    p.setPen(QPen(QColor("#3B3E58"), 2))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPath(clip)

    # icona e titolo
    QSvgRenderer(QByteArray(svg.encode("utf-8"))).render(p, QRectF(64, 140, 116, 116))
    p.setFont(font(64, QFont.Weight.Bold))
    p.setPen(QColor(TESTO))
    p.drawText(QPointF(200, 210), "P7MReader")
    p.setFont(font(20, QFont.Weight.DemiBold))
    p.setPen(QColor(ACCENTO))
    p.drawText(QPointF(203, 245), f"v{versione} · Windows · macOS · Linux · IT/EN")

    # slogan
    testo_ricco(p, 72, 316, [("Verifica le ", False, ATTENUATO), ("firme digitali", True, TESTO)], 27)
    testo_ricco(p, 72, 354, [("ed estrai i documenti dai ", False, ATTENUATO), (".p7m", True, TESTO), (",", False, ATTENUATO)], 27)
    testo_ricco(p, 72, 392, [("con la ", False, ATTENUATO), ("Trusted List AgID", True, TESTO), (" ed eIDAS.", False, ATTENUATO)], 27)

    # etichette
    righe = [[("CAdES .p7m", False), ("PAdES .pdf", False), ("XAdES .xml", False), ("FatturaPA", False)],
             [("QES · QSCD", True), ("Marca temporale", True), ("LOTL UE", True)]]
    y = 428
    for riga in righe:
        x = 72
        for t, verde in riga:
            p.setFont(font(18))
            w = p.fontMetrics().horizontalAdvance(t) + 32
            r = QRectF(x, y, w, 40)
            p.setBrush(QColor(92, 211, 160, 22) if verde else QColor(255, 255, 255, 14))
            p.setPen(QPen(QColor(92, 211, 160, 120) if verde else QColor(255, 255, 255, 40), 1))
            p.drawRoundedRect(r, 20, 20)
            p.setPen(QColor(VERDE if verde else TESTO))
            p.drawText(r, Qt.AlignmentFlag.AlignCenter, t)
            x += w + 10
        y += 50
    p.end()
    destinazione = os.path.join(RADICE, "docs", "social-preview.png")
    img.save(destinazione, "PNG")
    print("Creato", destinazione)
    del app


if __name__ == "__main__":
    main()
