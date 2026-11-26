"""Note della release ricavate dal changelog in testa a P7MReader.py.
Uso:  python packaging/note_release.py [versione] > note.md      (senza versione: APP_VERSION)

Prende la sezione della versione (es. "3.2.0 (2026-11-26)") fino alla successiva e la scrive in Markdown:
le righe che iniziano con "- " diventano voci di elenco, quelle rientrate continuano la voce precedente.
Gli accenti scritti con l'apostrofo nel sorgente (e', piu', perche') tornano accenti veri (è, più, perché).
Esce con 1 se il changelog non ha una sezione per quella versione: una release senza note non deve uscire.
"""
import os
import re
import sys

RADICE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TITOLO = re.compile(r"^(\d+(?:\.\d+)*)(?:\s+\(([^)]*)\))?\s*$")
_GRAVI = {"a": "à", "e": "è", "i": "ì", "o": "ò", "u": "ù"}


def _numeri(v: str):
    """'3.1' e '3.1.0' sono la stessa versione."""
    n = [int(x) for x in re.findall(r"\d+", v)]
    while n and n[-1] == 0:
        n.pop()
    return n


def accenti(testo: str) -> str:
    testo = re.sub(r"\b(\w*ch)e'(?=\W|$)", r"\1é", testo)          # perche', poiche' -> perché, poiché
    testo = re.sub(r"\b(\w*?)([aeiou])'(?=\W|$)", lambda m: m.group(1) + _GRAVI[m.group(2)], testo)
    return testo.replace(" -> ", " → ")


def sezione(sorgente: str, versione: str):
    """(data, righe) della sezione del changelog per 'versione', oppure None."""
    doc = re.match(r'\s*"""(.*?)"""', sorgente, re.S)
    if not doc or "Changelog" not in doc.group(1):
        return None
    righe = doc.group(1).split("Changelog", 1)[1].splitlines()
    dentro, data, corpo = False, "", []
    for r in righe:
        m = _TITOLO.match(r.strip()) if r and not r.startswith((" ", "-")) else None
        if m:
            if dentro:
                break
            dentro = _numeri(m.group(1)) == _numeri(versione)
            data = m.group(2) or ""
            continue
        if dentro:
            corpo.append(r)
    return (data, corpo) if dentro or corpo else None


def markdown(corpo) -> str:
    voci = []
    for r in corpo:
        if r.startswith("- "):
            voci.append(r[2:].strip())
        elif r.strip() and voci:
            voci[-1] += " " + r.strip()
        elif r.strip():
            voci.append(r.strip())
    return "\n".join(f"- {accenti(v)}" for v in voci)


def main() -> int:
    sorgente = open(os.path.join(RADICE, "P7MReader.py"), encoding="utf-8").read()
    versione = (sys.argv[1] if len(sys.argv) > 1 else
                re.search(r'APP_VERSION = "([^"]+)"', sorgente).group(1)).lstrip("vV")
    trovata = sezione(sorgente, versione)
    if trovata is None or not markdown(trovata[1]):
        print(f"[ERRORE] Il changelog di P7MReader.py non ha una sezione per la versione {versione}", file=sys.stderr)
        return 1
    data, corpo = trovata
    testo = [f"## Novità della versione {versione}" + (f" ({data})" if data else ""), "", markdown(corpo), "",
             "Scarica il file per il tuo sistema qui sotto e, se vuoi, controllalo con `SHA256SUMS.txt`. "
             "Dalla 3.2.0 P7MReader si aggiorna anche da solo (*Impostazioni → Aggiornamenti*).", ""]
    sys.stdout.reconfigure(encoding="utf-8")
    print("\n".join(testo))
    return 0


if __name__ == "__main__":
    sys.exit(main())
