# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from PyInstaller.utils.hooks import collect_all

datas = [('TSL-IT.xml', '.')]
binaries = []
# cryptography per Python 3.15 si lega a python3t.dll, che PyInstaller non include da solo
dll = os.path.join(sys.base_prefix, 'abi3t-compat', 'python3t.dll')
if os.path.exists(dll):
    binaries.append((dll, '.'))
hiddenimports = ['PyQt6.QtSvg']
for pacchetto in ('pyhanko', 'pyhanko_certvalidator', 'asn1crypto', 'lxml'):
    tmp_ret = collect_all(pacchetto)
    datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['P7MReader v3.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'customtkinter', 'tkinterdnd2', 'matplotlib', 'numpy', 'scipy', 'pandas', 'PIL',
              'PyQt6.QtWebEngineCore', 'PyQt6.QtWebEngineWidgets'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='P7MReader',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['P7MReader v3.ico'],
)
