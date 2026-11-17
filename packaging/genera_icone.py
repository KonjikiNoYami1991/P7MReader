"""Genera le icone del programma (PNG per Linux, ICNS per macOS) dall'SVG incluso nel sorgente.
L'icona Windows (P7MReader.ico) e' gia' nel repository e non viene toccata.
Uso:  python packaging/genera_icone.py        (richiede PyQt6 e Pillow)"""
import os
import re
import sys

QUI = os.path.dirname(os.path.abspath(__file__))
RADICE = os.path.dirname(QUI)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QByteArray, QRectF, Qt          # noqa: E402
from PyQt6.QtGui import QGuiApplication, QImage, QPainter  # noqa: E402
from PyQt6.QtSvg import QSvgRenderer                      # noqa: E402


def leggi_svg() -> str:
    testo = open(os.path.join(RADICE, "P7MReader.py"), encoding="utf-8").read()
    return re.search(r'ICON_SVG = """(.*?)"""', testo, re.S).group(1)


def main():
    app = QGuiApplication(sys.argv)
    rend = QSvgRenderer(QByteArray(leggi_svg().encode("utf-8")))
    img = QImage(1024, 1024, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    rend.render(p, QRectF(0, 0, 1024, 1024))
    p.end()
    png = os.path.join(RADICE, "P7MReader.png")
    img.save(png, "PNG")
    from PIL import Image
    Image.open(png).save(os.path.join(RADICE, "P7MReader.icns"))
    print("Icone generate in", RADICE)
    del app


if __name__ == "__main__":
    main()
