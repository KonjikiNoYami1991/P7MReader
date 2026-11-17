# -*- mode: python ; coding: utf-8 -*-
# Spec PyInstaller multipiattaforma per P7MReader.
#   Windows : python -m PyInstaller P7MReader.spec      -> dist\P7MReader.exe (un solo file)
#   macOS   : python -m PyInstaller P7MReader.spec      -> dist/P7MReader.app
#   Linux   : python -m PyInstaller P7MReader.spec      -> dist/P7MReader/ (poi AppImage con build_p7mreader.sh)
# Variabile P7M_ONEDIR=1 su Windows: cartella al posto del singolo exe (avvio piu' veloce, meno falsi positivi AV).
import os
import re
import sys

from PyInstaller.utils.hooks import collect_all

VERSIONE = re.search(r'APP_VERSION = "([^"]+)"', open("P7MReader.py", encoding="utf-8").read()).group(1)
IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
ONEFILE = IS_WIN and os.environ.get("P7M_ONEDIR") != "1"

datas = [("TSL-IT.xml", ".")]                     # copia offline della Trusted List AgID (firmata, verificata all'avvio)
binaries = []
if IS_WIN:
    # cryptography per Python 3.15 si lega a python3t.dll, che PyInstaller non include da solo
    dll = os.path.join(sys.base_prefix, "abi3t-compat", "python3t.dll")
    if os.path.exists(dll):
        binaries.append((dll, "."))
hiddenimports = ["PyQt6.QtSvg", "traduzioni_en"]
for pacchetto in ("pyhanko", "pyhanko_certvalidator", "asn1crypto", "lxml"):
    d, b, h = collect_all(pacchetto)
    datas += d
    binaries += b
    hiddenimports += h
try:
    import certifi  # noqa: F401  radici di sistema su macOS / Linux
    hiddenimports.append("certifi")
except ImportError:
    pass

if IS_WIN:
    icona = "P7MReader.ico"
elif IS_MAC:
    icona = "P7MReader.icns"
else:
    icona = "P7MReader.png"
icona = [icona] if os.path.exists(icona) else None

a = Analysis(
    ["P7MReader.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "customtkinter", "tkinterdnd2", "matplotlib", "numpy", "scipy", "pandas", "PIL",
              "PyQt6.QtWebEngineCore", "PyQt6.QtWebEngineWidgets", "PyQt6.QtQml", "PyQt6.QtQuick"],
    noarchive=False,
    optimize=0,
)
# delle traduzioni di Qt servono solo italiano e inglese (pulsanti standard e finestre di scelta file)
_ALTRE_LINGUE = re.compile(r"translations[/\\]\w+_(?!(it|en)\.qm$)[\w-]+\.qm$")
a.datas = [d for d in a.datas if not _ALTRE_LINGUE.search(d[0].replace("\\", "/"))]

pyz = PYZ(a.pure)
versione_win = "version_info.txt" if IS_WIN and os.path.exists("version_info.txt") else None

if ONEFILE:
    exe = EXE(
        pyz, a.scripts, a.binaries, a.datas, [],
        name="P7MReader",
        debug=False, bootloader_ignore_signals=False, strip=False, upx=False, upx_exclude=[],
        runtime_tmpdir=None, console=False, disable_windowed_traceback=False,
        argv_emulation=False, target_arch=None, codesign_identity=None, entitlements_file=None,
        version=versione_win, icon=icona,
    )
else:
    exe = EXE(
        pyz, a.scripts, [],
        exclude_binaries=True,
        name="P7MReader",
        debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
        console=False, disable_windowed_traceback=False,
        argv_emulation=False, target_arch=None, codesign_identity=None, entitlements_file=None,
        version=versione_win, icon=icona,
    )
    coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, upx_exclude=[], name="P7MReader")

if IS_MAC:
    def tipo(nome, estensioni):
        return {"CFBundleTypeName": nome, "CFBundleTypeRole": "Viewer", "LSHandlerRank": "Alternate",
                "CFBundleTypeExtensions": estensioni}

    app = BUNDLE(
        coll,
        name="P7MReader.app",
        icon=icona[0] if icona else None,
        bundle_identifier="io.github.konjikinoyami1991.p7mreader",
        version=VERSIONE,
        info_plist={
            "CFBundleName": "P7MReader",
            "CFBundleDisplayName": "P7MReader",
            "CFBundleShortVersionString": VERSIONE,
            "CFBundleVersion": VERSIONE,
            "LSMinimumSystemVersion": "12.0",
            "NSHighResolutionCapable": True,
            "NSRequiresAquaSystemAppearance": False,
            "LSApplicationCategoryType": "public.app-category.productivity",
            "CFBundleDocumentTypes": [
                tipo("Signed document", ["p7m", "p7s"]),
                tipo("Signed PDF", ["pdf"]),
                tipo("Signed XML / FatturaPA", ["xml"]),
            ],
        },
    )
