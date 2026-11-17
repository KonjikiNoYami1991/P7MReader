"""Legge APP_VERSION da P7MReader.py, riallinea version_info.txt (proprieta' dell'exe) e stampa la versione.
Uso:  python packaging/versione.py"""
import os
import re

RADICE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sorgente = open(os.path.join(RADICE, "P7MReader.py"), encoding="utf-8").read()
versione = re.search(r'APP_VERSION = "([^"]+)"', sorgente).group(1)
numeri = [int(x) for x in re.findall(r"\d+", versione)][:4]
numeri += [0] * (4 - len(numeri))
tupla, testo = "(%d, %d, %d, %d)" % tuple(numeri), "%d.%d.%d.%d" % tuple(numeri)

percorso = os.path.join(RADICE, "version_info.txt")
info = open(percorso, encoding="utf-8").read()
info = re.sub(r"(filevers|prodvers)=\([^)]*\)", lambda m: f"{m.group(1)}={tupla}", info)
info = re.sub(r"(StringStruct\('(?:FileVersion|ProductVersion)', ')[^']*'", lambda m: f"{m.group(1)}{testo}'", info)
with open(percorso, "w", encoding="utf-8", newline="\n") as f:
    f.write(info)
print(versione)
