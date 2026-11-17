@echo off
rem ============================================================
rem  Build di P7MReader per Windows con PyInstaller
rem  Uso:   build_p7mreader.bat            -> un solo exe in dist\
rem         build_p7mreader.bat onedir     -> cartella dist\P7MReader\ (avvio piu' veloce)
rem  Dopo la compilazione l'exe viene avviato con --selftest e ne viene calcolato lo SHA-256.
rem ============================================================
setlocal
cd /d "%~dp0"

set "P7M_ONEDIR="
if /i "%~1"=="onedir" set "P7M_ONEDIR=1"

echo.
echo [1/4] Installo/aggiorno le dipendenze...
python -m pip install --upgrade pyinstaller PyQt6 pyhanko pyhanko-certvalidator asn1crypto cryptography lxml certifi
if errorlevel 1 goto errore

echo.
echo [2/4] Versione e informazioni dell'exe...
for /f "delims=" %%V in ('python packaging\versione.py') do set "VERSIONE=%%V"
if not defined VERSIONE goto errore
echo       P7MReader %VERSIONE%

echo.
echo [3/4] Compilazione in corso...
python -m PyInstaller --noconfirm --clean P7MReader.spec
if errorlevel 1 goto errore
if exist build rmdir /s /q build

set "EXE=dist\P7MReader.exe"
if defined P7M_ONEDIR set "EXE=dist\P7MReader\P7MReader.exe"

echo.
echo [4/4] Prova di avvio (--selftest) e impronta...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = Start-Process -FilePath '%EXE%' -ArgumentList '--selftest' -Wait -PassThru; exit $p.ExitCode"
if errorlevel 1 (
    echo [ERRORE] Il selftest dell'exe e' fallito: dettagli in %%APPDATA%%\P7MReader\errori.log
    goto errore
)
certutil -hashfile "%EXE%" SHA256 | findstr /v ":"

echo.
echo ============================================================
echo  FATTO! P7MReader %VERSIONE% in: %EXE%
echo ============================================================
explorer dist
pause
exit /b 0

:errore
echo.
echo [ERRORE] La build e' fallita: controlla i messaggi qui sopra.
pause
exit /b 1
