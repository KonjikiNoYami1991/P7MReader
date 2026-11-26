"""Aggiorna la copia della Trusted List AgID inclusa nei pacchetti (TSL-IT.xml), se ne esiste una piu' recente.
Uso:  python packaging/aggiorna_tsl.py

- Scarica la lista ufficiale e la sostituisce solo se il numero di sequenza (TSLSequenceNumber) e' maggiore.
- Non controlla qui la firma: lo fa P7MReader all'avvio, e una copia con firma non integra non viene mai
  caricata (il --selftest dopo la compilazione fallirebbe). Questo script si limita a non peggiorare le cose.
- Se il download non riesce il pacchetto si compila con la copia gia' presente: l'errore non e' fatale.
"""
import os
import re
import ssl
import sys
import urllib.request

URL_TSL = "https://eidas.agid.gov.it/TL/TSL-IT.xml"
RADICE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE_TSL = os.path.join(RADICE, "TSL-IT.xml")
_SEQ = re.compile(rb"<(?:\w+:)?TSLSequenceNumber>\s*(\d+)\s*<")
_DATA = re.compile(rb"<(?:\w+:)?ListIssueDateTime>\s*([^<]+?)\s*<")


def _info(dati: bytes):
    seq, data = _SEQ.search(dati), _DATA.search(dati)
    return (int(seq.group(1)) if seq else -1), (data.group(1).decode("ascii", "replace") if data else "?")


def main() -> int:
    with open(FILE_TSL, "rb") as f:
        seq_locale, data_locale = _info(f.read())
    try:
        try:
            import certifi
            contesto = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            contesto = ssl.create_default_context()
        richiesta = urllib.request.Request(URL_TSL, headers={"User-Agent": "P7MReader-build"})
        with urllib.request.urlopen(richiesta, timeout=60, context=contesto) as r:
            nuova = r.read()
    except Exception as e:  # rete assente o sito non raggiungibile: si tiene la copia presente
        print(f"[AVVISO] Trusted List non scaricabile ({e}): resta la n. {seq_locale} del {data_locale}")
        return 0
    seq_nuova, data_nuova = _info(nuova)
    if b"TrustServiceStatusList" not in nuova[:4096] or seq_nuova < 0:
        print(f"[AVVISO] Il file scaricato non sembra una Trusted List: resta la n. {seq_locale} del {data_locale}")
        return 0
    if seq_nuova <= seq_locale:
        print(f"Trusted List gia' aggiornata: n. {seq_locale} del {data_locale}")
        return 0
    with open(FILE_TSL, "wb") as f:
        f.write(nuova)
    print(f"Trusted List aggiornata: n. {seq_locale} del {data_locale} -> n. {seq_nuova} del {data_nuova}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
