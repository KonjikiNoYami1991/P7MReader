"""Prova dell'aggiornatore integrato, senza GitHub e senza toccare il programma vero.
Uso:  python packaging/prova_aggiornamento.py

Un server HTTP locale fa la parte della release (latest.json, pacchetto, SHA256SUMS.txt); il programma installato e'
finto e sta in una cartella temporanea. Si prova il modo di installazione di questo sistema:
  Windows -> exe singolo (script .cmd)      macOS -> app dentro un .dmg (hdiutil + ditto)
  Linux   -> tar.gz installato e AppImage
e in piu': impronta SHA-256 manomessa (deve essere respinta) e versione uguale (non deve risultare nuova).
Esce con 0 se tutto va come deve.
"""
import functools
import hashlib
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

RADICE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, RADICE)
os.chdir(RADICE)
import P7MReader as P  # noqa: E402

LAVORO = tempfile.mkdtemp(prefix="p7m-prova-agg-")
SRV, INST = os.path.join(LAVORO, "srv"), os.path.join(LAVORO, "inst")
os.makedirs(SRV)
os.makedirs(INST)
ERRORI = []


def esito(nome, ok, dettaglio=""):
    print(f"[{'OK' if ok else 'KO'}] {nome}" + (f": {dettaglio}" if dettaglio else ""), flush=True)
    if not ok:
        ERRORI.append(nome)


def attendi(condizione, secondi=60):
    fine = time.time() + secondi
    while time.time() < fine:
        if condizione():
            return True
        time.sleep(0.5)
    return False


def pubblica(pacchetti, tag="v99.0.0"):
    for nome, dati in pacchetti.items():
        with open(os.path.join(SRV, nome), "wb") as f:
            f.write(dati)
    with open(os.path.join(SRV, "SHA256SUMS.txt"), "w") as f:
        f.write("".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in pacchetti.items()))
    risorse = [{"name": n, "browser_download_url": f"{BASE}/{n}", "size": len(d)} for n, d in pacchetti.items()]
    risorse.append({"name": "SHA256SUMS.txt", "browser_download_url": f"{BASE}/SHA256SUMS.txt", "size": 1})
    with open(os.path.join(SRV, "latest.json"), "w") as f:
        json.dump({"tag_name": tag, "html_url": BASE, "body": "- prova", "assets": risorse}, f)


def esegui_script(comando):
    """Lo script aspetta l'uscita di questo processo: per la prova gli si da' un PID gia' terminato."""
    pid = str(os.getpid())
    percorso = comando[-1]
    with open(percorso, encoding="utf-8") as f:
        testo = f.read()
    testo = testo.replace(f"PID eq {pid}", "PID eq 999999").replace(f'find "{pid}"', 'find "999999"')
    testo = testo.replace(f"kill -0 {pid}", "kill -0 999999")
    with open(percorso, "w", encoding="utf-8", newline="\r\n" if percorso.endswith(".cmd") else "\n") as f:
        f.write(testo)
    P._avvia_staccato(comando)
    return percorso


class Silenzioso(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Silenzioso, directory=SRV))
threading.Thread(target=server.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{server.server_address[1]}"
P.URL_ULTIMA_RELEASE = f"{BASE}/latest.json"
sys.frozen = True


def prova_windows():
    cartella = os.path.join(INST, "programmi")
    os.makedirs(cartella)
    exe = os.path.join(cartella, "P7MReader-3.0.0-windows-x64.exe")
    with open(exe, "wb") as f:
        f.write(b"vecchio")
    sys.executable, sys._MEIPASS = exe, tempfile.mkdtemp(prefix="_MEI")
    # il "nuovo exe" e' una copia di where.exe: si avvia, non apre finestre e termina subito
    nuovo = open(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "where.exe"), "rb").read()
    pubblica({"P7MReader-99.0.0-windows-x64.exe": nuovo})
    return exe, nuovo


def prova_macos():
    sorgente = os.path.join(LAVORO, "dmg")
    for base, contenuto in ((os.path.join(sorgente, "P7MReader.app"), b"#!/bin/sh\nexit 0\n# nuova\n"),
                            (os.path.join(INST, "P7MReader.app"), b"#!/bin/sh\nexit 0\n# vecchia\n")):
        os.makedirs(os.path.join(base, "Contents", "MacOS"))
        with open(os.path.join(base, "Contents", "MacOS", "P7MReader"), "wb") as f:
            f.write(contenuto)
        os.chmod(os.path.join(base, "Contents", "MacOS", "P7MReader"), 0o755)
    dmg = os.path.join(LAVORO, "nuovo.dmg")
    subprocess.run(["hdiutil", "create", "-volname", "P7MReader", "-srcfolder", sorgente, "-ov", "-format", "UDZO", dmg],
                   check=True, capture_output=True)
    sys.executable = os.path.join(INST, "P7MReader.app", "Contents", "MacOS", "P7MReader")
    suffisso = P.suffisso_pacchetto()
    pubblica({f"P7MReader-99.0.0{suffisso}": open(dmg, "rb").read()})
    return sys.executable, b"# nuova"


def prova_linux_cartella():
    cartella = os.path.join(INST, "opt", "p7mreader")
    os.makedirs(os.path.join(cartella, "_internal"))
    with open(os.path.join(cartella, "P7MReader"), "w") as f:
        f.write("vecchio")
    sys.executable = os.path.join(cartella, "P7MReader")
    os.environ.pop("APPIMAGE", None)
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for nome, dati, modo in (("P7MReader-99.0.0-linux-x86_64/P7MReader/P7MReader", b"#!/bin/sh\n# nuova\n", 0o755),
                                 ("P7MReader-99.0.0-linux-x86_64/P7MReader/_internal/v.txt", b"99.0.0", 0o644)):
            ti = tarfile.TarInfo(nome)
            ti.size, ti.mode = len(dati), modo
            t.addfile(ti, io.BytesIO(dati))
    pubblica({"P7MReader-99.0.0-linux-x86_64.tar.gz": b.getvalue()})
    return sys.executable, b"# nuova"


def prova_linux_appimage():
    ai = os.path.join(INST, "P7MReader-3.0.0-x86_64.AppImage")
    with open(ai, "w") as f:
        f.write("vecchia")
    os.environ["APPIMAGE"] = ai
    nuova = b"#!/bin/sh\nexit 0\n# nuova appimage\n"
    pubblica({"P7MReader-99.0.0-x86_64.AppImage": nuova})
    return ai, nuova


def installa(nome, preparazione):
    bersaglio, atteso = preparazione()
    modo = P.tipo_installazione()[0]
    info = P.controlla_aggiornamenti()
    esito(f"{nome}: release trovata", info["nuova"] and info["pacchetto"] is not None,
          f"{info['versione']} · {info['pacchetto'] and info['pacchetto']['nome']} · modo {modo}")
    esito(f"{nome}: sostituibile", P.puo_sostituirsi())
    passi = []
    scaricato = P.scarica_verificato(info, os.path.dirname(P.tipo_installazione()[1]), lambda a, b: passi.append(a))
    esito(f"{nome}: scaricato e verificato", os.path.isfile(scaricato) and passi, os.path.basename(scaricato))
    script = esegui_script(P.prepara_installazione(scaricato))
    sostituito = attendi(lambda: os.path.isfile(bersaglio) and atteso in open(bersaglio, "rb").read())
    esito(f"{nome}: programma sostituito", sostituito, bersaglio)
    esito(f"{nome}: script rimosso", attendi(lambda: not os.path.exists(script), 20), script)
    return info


if sys.platform == "win32":
    info = installa("Windows exe", prova_windows)
elif sys.platform == "darwin":
    info = installa("macOS app", prova_macos)
    esito("macOS: nessun residuo", attendi(lambda: sorted(os.listdir(INST)) == ["P7MReader.app"], 20), str(os.listdir(INST)))
else:
    installa("Linux tar.gz", prova_linux_cartella)
    esito("Linux tar.gz: nessun residuo", attendi(lambda: os.listdir(os.path.join(INST, "opt")) == ["p7mreader"], 20),
          str(os.listdir(os.path.join(INST, "opt"))))
    info = installa("Linux AppImage", prova_linux_appimage)
    esito("Linux AppImage: eseguibile", os.access(os.environ["APPIMAGE"], os.X_OK))

# file manomesso dopo la pubblicazione delle impronte: deve essere respinto e non lasciare nulla
nome = info["pacchetto"]["nome"]
with open(os.path.join(SRV, nome), "ab") as f:
    f.write(b"manomesso")
prima = set(os.listdir(LAVORO))
try:
    P.scarica_verificato(P.controlla_aggiornamenti(), LAVORO)
    esito("impronta manomessa respinta", False, "il file e' stato accettato")
except ValueError as e:
    esito("impronta manomessa respinta", set(os.listdir(LAVORO)) == prima, str(e))

with open(os.path.join(SRV, "latest.json")) as f:
    rel = json.load(f)
rel["tag_name"] = "v" + P.APP_VERSION
with open(os.path.join(SRV, "latest.json"), "w") as f:
    json.dump(rel, f)
esito("stessa versione non e' nuova", not P.controlla_aggiornamenti()["nuova"])
esito("confronto versioni", P.numeri_versione("v3.2") == P.numeri_versione("3.2.0") and
      P.numeri_versione("v3.10.0") > P.numeri_versione("3.9.9"))

server.shutdown()
shutil.rmtree(LAVORO, ignore_errors=True)
print("Tutto bene" if not ERRORI else f"Prove fallite: {', '.join(ERRORI)}")
sys.exit(1 if ERRORI else 0)
