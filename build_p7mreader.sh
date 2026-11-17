#!/usr/bin/env bash
# ============================================================
#  Build di P7MReader per macOS e Linux con PyInstaller
#  Uso:   ./build_p7mreader.sh
#  macOS -> dist/P7MReader.app  +  dist/P7MReader-<ver>-macOS-<arch>.dmg
#  Linux -> dist/P7MReader-<ver>-x86_64.AppImage  +  dist/P7MReader-<ver>-linux-<arch>.tar.gz
#  Variabili facoltative:
#    PYTHON=python3.13   interprete da usare (default: python3)
#    NO_VENV=1           usa l'interprete cosi' com'e', senza creare .venv-build
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

NOME="P7MReader"
ARCH="$(uname -m)"
OS="$(uname -s)"
PYTHON="${PYTHON:-python3}"

echo "[1/4] Ambiente Python..."
if [ "${NO_VENV:-0}" != "1" ]; then
    [ -d .venv-build ] || "$PYTHON" -m venv .venv-build
    # shellcheck disable=SC1091
    . .venv-build/bin/activate
    PYTHON=python
fi
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install --upgrade pyinstaller PyQt6 asn1crypto pyhanko pyhanko-certvalidator cryptography lxml certifi tzdata pillow
VERSIONE="$("$PYTHON" packaging/versione.py)"

echo "[2/4] Icone..."
[ -f P7MReader.png ] && [ -f P7MReader.icns ] || "$PYTHON" packaging/genera_icone.py

echo "[3/4] Compilazione con PyInstaller (versione $VERSIONE)..."
rm -rf build "dist/$NOME" "dist/$NOME.app"
"$PYTHON" -m PyInstaller --noconfirm --clean P7MReader.spec

echo "[4/4] Pacchetto..."
if [ "$OS" = "Darwin" ]; then
    DMG="dist/$NOME-$VERSIONE-macOS-$ARCH.dmg"
    STAGE="$(mktemp -d)"
    cp -R "dist/$NOME.app" "$STAGE/"
    ln -s /Applications "$STAGE/Applications"
    rm -f "$DMG"
    hdiutil create -volname "$NOME $VERSIONE" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
    rm -rf "$STAGE"
    echo "Fatto: dist/$NOME.app e $DMG"
else
    # --- tar.gz con installazione per l'utente ---
    PACK="dist/$NOME-$VERSIONE-linux-$ARCH"
    rm -rf "$PACK" && mkdir -p "$PACK"
    cp -a "dist/$NOME" "$PACK/"
    cp packaging/p7mreader.desktop packaging/installa-linux.sh "$PACK/"
    cp P7MReader.png "$PACK/p7mreader.png"
    tar -C dist -czf "$PACK.tar.gz" "$(basename "$PACK")"
    rm -rf "$PACK"

    # --- AppImage ---
    APPDIR="build/AppDir"
    rm -rf "$APPDIR"
    mkdir -p "$APPDIR/usr/lib" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps"
    cp -a "dist/$NOME" "$APPDIR/usr/lib/p7mreader"
    cp packaging/AppRun "$APPDIR/AppRun" && chmod +x "$APPDIR/AppRun"
    cp packaging/p7mreader.desktop "$APPDIR/p7mreader.desktop"
    cp packaging/p7mreader.desktop "$APPDIR/usr/share/applications/"
    QT_QPA_PLATFORM=offscreen "$PYTHON" - <<'EOF'
from PyQt6.QtGui import QImage
from PyQt6.QtCore import Qt
img = QImage("P7MReader.png").scaled(256, 256, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
img.save("build/AppDir/p7mreader.png")
img.save("build/AppDir/usr/share/icons/hicolor/256x256/apps/p7mreader.png")
EOF
    ln -sf p7mreader.png "$APPDIR/.DirIcon"

    TOOL="build/appimagetool-$ARCH.AppImage"
    if [ ! -x "$TOOL" ]; then
        curl -fsSL -o "$TOOL" "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$ARCH.AppImage" \
            && chmod +x "$TOOL" || { echo "[AVVISO] appimagetool non scaricabile: niente AppImage (resta il .tar.gz)."; TOOL=""; }
    fi
    if [ -n "$TOOL" ]; then
        ARCH="$ARCH" APPIMAGE_EXTRACT_AND_RUN=1 "$TOOL" --no-appstream "$APPDIR" "dist/$NOME-$VERSIONE-$ARCH.AppImage"
        echo "Fatto: dist/$NOME-$VERSIONE-$ARCH.AppImage"
    fi
    echo "Fatto: $PACK.tar.gz"
fi
rm -rf build
