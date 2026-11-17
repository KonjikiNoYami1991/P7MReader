@echo off
rem ============================================================
rem  Build di P7MReader 3.0 con PyInstaller (un solo .exe in dist\)
rem ============================================================
setlocal
cd /d "%~dp0"

echo.
echo [1/3] Installo/aggiorno le dipendenze...
python -m pip install --upgrade pyinstaller PyQt6 pyhanko pyhanko-certvalidator asn1crypto cryptography lxml
if errorlevel 1 goto errore

echo.
echo [2/3] Compilazione in corso...
python -m PyInstaller --noconfirm --clean "P7MReader v3.spec"
if errorlevel 1 goto errore

echo.
echo [3/3] Pulizia file temporanei di build...
if exist build rmdir /s /q build

echo.
echo  FATTO! Programma in: dist\P7MReader.exe
explorer dist
pause
exit /b 0

:errore
echo.
echo [ERRORE] La build e' fallita: controlla i messaggi qui sopra.
pause
exit /b 1
