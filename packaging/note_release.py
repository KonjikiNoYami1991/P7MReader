"""Note della release ricavate dal changelog in testa a P7MReader.py.
Uso:  python packaging/note_release.py [versione] > note.md      (senza versione: APP_VERSION)

Prende la sezione della versione (es. "3.2.0 (2026-11-26)") fino alla successiva e la scrive in Markdown:
le righe che iniziano con "- " diventano voci di elenco, quelle rientrate continuano la voce precedente.
Gli accenti scritti con l'apostrofo nel sorgente (e', piu', perche') tornano accenti veri (è, più, perché).
Esce con 1 se il changelog non ha una sezione per quella versione: una release senza note non deve uscire.

In piu':
- le versioni dello stesso ramo senza una release propria (es. la 3.1, uscita direttamente come 3.1.1) finiscono
  nelle note della prima release che le contiene, cosi' le loro novita' non restano fuori da GitHub;
- la tabella dei pacchetti (un file per sistema) con le istruzioni per il primo avvio su macOS;
- nelle release precedenti all'ultima, il rimando alla versione piu' recente.
"""
import os
import re
import subprocess
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


def versioni_changelog(sorgente: str):
    """[(versione, data)] dei titoli del changelog, dalla piu' recente."""
    doc = re.match(r'\s*"""(.*?)"""', sorgente, re.S)
    if not doc or "Changelog" not in doc.group(1):
        return []
    out = []
    for r in doc.group(1).split("Changelog", 1)[1].splitlines():
        m = _TITOLO.match(r.strip()) if r and not r.startswith((" ", "-")) else None
        if m:
            out.append((m.group(1), m.group(2) or ""))
    return out


def versioni_pubblicate():
    """Versioni con un tag v* su GitHub (None se non si riesce a saperlo: allora non si aggiunge nulla)."""
    try:
        r = subprocess.run(["git", "ls-remote", "--tags", "origin"], cwd=RADICE, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None
        return {tuple(_numeri(m)) for m in re.findall(r"refs/tags/v([\d.]+)$", r.stdout, re.M)}
    except Exception:
        return None


def pacchetti(versione: str) -> str:
    righe = [("Windows 10/11 (x64)", f"P7MReader-{versione}-windows-x64.exe"),
             ("macOS 12+ Apple Silicon", f"P7MReader-{versione}-macOS-arm64.dmg"),
             ("macOS 12+ Intel", f"P7MReader-{versione}-macOS-x86_64.dmg"),
             ("Linux x86_64 (Debian 12+, Ubuntu 22.04+, Fedora, Arch, openSUSE, RHEL 9+…)",
              f"P7MReader-{versione}-x86_64.AppImage` oppure `P7MReader-{versione}-linux-x86_64.tar.gz")]
    return "\n".join(["## Pacchetti", "", "| Sistema | File |", "|---|---|"] + [f"| {s} | `{f}` |" for s, f in righe] + [
        "", "Su macOS l'app non è firmata da Apple: al primo avvio, su macOS 15 e successivi *Impostazioni di Sistema → "
            "Privacy e sicurezza → Apri comunque*, su macOS 12-14 *clic destro sull'app → Apri* "
            "([istruzioni](https://github.com/KonjikiNoYami1991/P7MReader#primo-avvio-su-macos))."])


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
    testo = [f"## Novità della versione {versione}" + (f" ({data})" if data else ""), "", markdown(corpo), ""]
    # versioni dello stesso ramo (es. 3.1 per la 3.1.1) uscite senza una release propria
    pubblicate = versioni_pubblicate()
    if pubblicate is not None:
        elenco = versioni_changelog(sorgente)
        mie = _numeri(versione)
        indice = next((i for i, (v, _d) in enumerate(elenco) if _numeri(v) == mie), None)
        for v, d in (elenco[indice + 1:] if indice is not None else []):
            n = _numeri(v)
            if tuple(n) in pubblicate or n[:2] != mie[:2]:
                break
            sotto = sezione(sorgente, v)
            if sotto and markdown(sotto[1]):
                testo += [f"### Comprende anche la versione {v}" + (f" ({d})" if d else "") + ", uscita senza una release propria",
                          "", markdown(sotto[1]), ""]
    testo += [pacchetti(versione), "",
              "Se vuoi, controlla il file scaricato con `SHA256SUMS.txt`. "
              "Dalla 3.2.0 P7MReader si aggiorna anche da solo (*Impostazioni → Aggiornamenti*).", ""]
    attuale = re.search(r'APP_VERSION = "([^"]+)"', sorgente).group(1)
    if _numeri(versione) < _numeri(attuale):
        testo += [f"> È disponibile una versione più recente: [P7MReader {attuale}]"
                  f"(https://github.com/KonjikiNoYami1991/P7MReader/releases/latest).", ""]
    sys.stdout.reconfigure(encoding="utf-8")
    print("\n".join(testo))
    return 0


if __name__ == "__main__":
    sys.exit(main())
