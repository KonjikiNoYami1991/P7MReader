"""
P7MReader 3.0 - Verifica firme digitali ed estrazione documenti
Supporto: CAdES (.p7m, .p7s, anche annidati / base64), PAdES (.pdf), XAdES (.xml, fatture elettroniche)

Novita' rispetto alla 2.0
- Interfaccia a schede (Inizio, Verifica, Estrazione, Impostazioni) in PyQt6, con 3 temi
- Tabella unica per verifica ed estrazione massiva, con dettagli espandibili: per ogni firma l'elenco dei controlli
- Marca temporale verificata davvero (impronta, firma, TSA): se e' valida la firma si valuta a quella data
- XAdES: verifica crittografica reale (riferimenti, trasformazioni, SignedInfo), prima assente
- Controfirme verificate, legame signing-certificate, algoritmi deboli, data di firma fuori validita',
  revoca non determinabile segnalata, certificati qualificati riconosciuti
- Firme .p7s / detached verificate sul file accanto; tipo del file riconosciuto dal contenuto
- Nomi puliti: via i vari ".pdf (1) (1).p7m", ".p7m (2)", " - Copia"; estensione ricavata dal contenuto
"""
from __future__ import annotations

import os
import sys
import re
import io
import ssl
import csv
import json
import html
import logging
import math
import time
import base64
import queue
import hashlib
import asyncio
import zipfile
import tempfile
import datetime
import threading
import subprocess
import traceback
import weakref
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from PyQt6 import sip
from PyQt6.QtCore import Qt, QObject, QThread, QTimer, QSize, QRectF, QPointF, QByteArray, pyqtSignal
from PyQt6.QtGui import (QIcon, QPixmap, QPainter, QPen, QColor, QPolygonF, QLinearGradient, QGuiApplication,
                         QAction, QKeySequence, QShortcut)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton,
                             QLabel, QLineEdit, QFrame, QTabWidget, QScrollArea, QStackedWidget, QTreeWidget,
                             QTreeWidgetItem, QStyledItemDelegate, QHeaderView, QAbstractItemView, QProgressBar,
                             QCheckBox, QComboBox, QFileDialog, QMessageBox, QDialog, QPlainTextEdit,
                             QMenu, QButtonGroup, QSizePolicy, QTextBrowser)

from asn1crypto import cms, x509, pem, tsp
from asn1crypto.core import Void
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import PathValidationError

try:
    from pyhanko.sign.validation import async_validate_pdf_signature
except ImportError:
    async_validate_pdf_signature = None
try:
    from pyhanko.sign.validation import validate_pdf_signature
except ImportError:
    validate_pdf_signature = None
try:
    from pyhanko.sign.validation import async_validate_pdf_timestamp
except ImportError:
    async_validate_pdf_timestamp = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, dsa, ed25519, ed448
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from lxml import etree
except ImportError:
    etree = None

for _nome_log in ("pyhanko", "pyhanko_certvalidator"):      # gli esiti li gestisce il programma: niente traceback sul log
    logging.getLogger(_nome_log).setLevel(logging.CRITICAL)

APP_NAME = "P7MReader"
APP_VERSION = "3.0"
ESTENSIONI_VERIFICA = ('.p7m', '.p7s', '.pdf', '.xml')
ESTENSIONI_ESTRAI = ('.p7m',)
MAX_ANNIDAMENTO = 6
OID_TIMESTAMP_TOKEN = '1.2.840.113549.1.9.16.2.14'
OID_COUNTER_SIGNATURE = '1.2.840.113549.1.9.6'


# ============================================================ IMPOSTAZIONI
def cartella_config() -> str:
    base = os.environ.get("APPDATA") or os.path.join(os.path.expanduser("~"), ".config")
    percorso = os.path.join(base, APP_NAME)
    try:
        os.makedirs(percorso, exist_ok=True)
    except Exception:
        percorso = tempfile.gettempdir()
    return percorso


class Impostazioni:
    DEFAULT = {
        "tema": "System",              # System / Light / Dark
        "revoca": True,                # controllo OCSP/CRL (soft-fail)
        "valida_data_firma": True,     # se il certificato e' scaduto, valida alla data di firma dichiarata
        "estrai_annidati": True,       # scarta le buste p7m annidate
        "elimina_originale": False,    # elimina il .p7m dopo estrazione riuscita
        "sottocartelle": True,         # default scansione sottocartelle
        "cartella_output": "",         # vuoto = accanto all'originale
        "concorrenza": 4,
        "radici_extra": [],            # percorsi di certificati CA aggiuntivi
        "ultima_cartella": "",
        "verifica_in_estrazione": True, # durante l'estrazione verifica anche le firme
        "colonne_verifica": "",        # larghezze colonne salvate
        "colonne_estrai": "",
    }

    def __init__(self):
        self.path = os.path.join(cartella_config(), "impostazioni.json")
        self.d = dict(self.DEFAULT)
        self.carica()

    def carica(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                letto = json.load(f)
            for k in self.DEFAULT:
                if k in letto:
                    self.d[k] = letto[k]
        except Exception:
            pass

    def salva(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.d, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def __getitem__(self, k):
        return self.d.get(k, self.DEFAULT.get(k))

    def __setitem__(self, k, v):
        self.d[k] = v


IMP = Impostazioni()


# ============================================================ UTILITA'
_EST_BUSTA = ('.p7m', '.p7s')
_RE_SEGNO_COPIA = re.compile(r'\s*(?:[\(\[]\s*(\d+)\s*[\)\]]|-\s*cop(?:ia|y))\s*$', re.IGNORECASE)
_RE_ESTENSIONE = re.compile(r'\.[A-Za-z0-9]{1,8}$')


def _estensione_vera(s: str) -> bool:
    m = _RE_ESTENSIONE.search(s)
    return bool(m) and any(c.isalpha() for c in m.group(0))


def _togli_segni_copia(s: str) -> str:
    """Toglie dalla coda i segni di copia ripetuti: " (1)", "(1) (2)", "[1]", " - Copia", " - Copia (3)".
    Un numero di 4+ cifre resta, a meno che non venga dopo un'estensione: "Bilancio (2024)" e' un nome legittimo."""
    while True:
        s = s.rstrip(' .')
        m = _RE_SEGNO_COPIA.search(s)
        if not m or not s[:m.start()].rstrip(' .'):
            return s
        if m.group(1) and len(m.group(1)) > 3 and not _estensione_vera(s[:m.start()].rstrip(' .')):
            return s
        s = s[:m.start()]


def pulisci_nome_file_globale(filename: str) -> str:
    """"doc.pdf (1) (1).p7m", "doc.pdf.p7m (2)", "doc (3).pdf - Copia.p7m.p7m" -> "doc.pdf"."""
    nome = filename.strip()
    while True:
        nome = _togli_segni_copia(nome)
        base, ext = os.path.splitext(nome)
        if ext.lower() in _EST_BUSTA and base:
            nome = base
            continue
        break
    if nome.lower() in _EST_BUSTA:
        return "documento"
    while _estensione_vera(nome):
        base, ext = os.path.splitext(nome)
        pulita = _togli_segni_copia(base)
        if not pulita:
            break
        if pulita.lower().endswith(ext.lower()):     # "doc.pdf (1).pdf" -> "doc.pdf"
            nome = pulita
            continue
        nome = pulita + ext
        break
    return nome or "documento"


def tipo_documento(nome: str) -> str:
    """Estensione significativa di un file, ignorando i segni di copia in coda: "x.p7m (1)" -> ".p7m"."""
    n = nome.strip().rstrip(' .')
    while True:
        m = _RE_SEGNO_COPIA.search(n)
        if not m or not n[:m.start()]:
            break
        n = n[:m.start()].rstrip(' .')
    return os.path.splitext(n)[1].lower()


def supportato(nome: str, estensioni=ESTENSIONI_VERIFICA) -> bool:
    return tipo_documento(nome) in estensioni


def _sembra_der(dati: bytes) -> bool:
    """SEQUENCE DER/BER con lunghezza in forma lunga o indefinita: e' l'inizio di una busta CMS."""
    return len(dati) > 1 and dati[0] == 0x30 and dati[1] >= 0x80


def sniff_contenuto(dati: bytes) -> Tuple[str, str]:
    if _sembra_der(dati):
        return "Busta P7M", ".p7m"
    if b'%PDF-' in dati[:1024]:
        return "PDF", ".pdf"
    testa = dati[:300].lstrip(b'\xef\xbb\xbf \r\n\t')
    minuscolo = testa[:15].lower()
    if minuscolo.startswith((b'<!doctype html', b'<html')):
        return "HTML", ".html"
    if testa.startswith(b'<'):
        return "XML", ".xml"
    if dati[:3] == b'\xff\xd8\xff':
        return "JPEG", ".jpg"
    if dati[:8] == b'\x89PNG\r\n\x1a\n':
        return "PNG", ".png"
    if dati[:4] in (b'II*\x00', b'MM\x00*'):
        return "TIFF", ".tif"
    if dati[:6] in (b'GIF87a', b'GIF89a'):
        return "GIF", ".gif"
    if dati[:5] == b'{\\rtf':
        return "RTF", ".rtf"
    if dati[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return "Office 97-2003", ".doc"
    if dati[:6] == b'7z\xbc\xaf\x27\x1c':
        return "7-Zip", ".7z"
    if dati[:4] == b'Rar!':
        return "RAR", ".rar"
    if dati[:2] == b'PK':
        try:
            with zipfile.ZipFile(io.BytesIO(dati)) as z:
                nomi = set(z.namelist())
                if 'word/document.xml' in nomi:
                    return "Word", ".docx"
                if 'xl/workbook.xml' in nomi:
                    return "Excel", ".xlsx"
                if 'ppt/presentation.xml' in nomi:
                    return "PowerPoint", ".pptx"
                if 'mimetype' in nomi:
                    tipo = z.read('mimetype')
                    for chiave, risultato in ((b'opendocument.text', ("ODF Testo", ".odt")),
                                              (b'opendocument.spreadsheet', ("ODF Foglio", ".ods")),
                                              (b'opendocument.presentation', ("ODF Presentazione", ".odp"))):
                        if chiave in tipo:
                            return risultato
        except Exception:
            pass
        return "ZIP", ".zip"
    return "File", ""


_EST_DI_TIPO = {"PDF": {".pdf"}, "JPEG": {".jpg", ".jpeg", ".jpe", ".jfif"}, "PNG": {".png"}, "TIFF": {".tif", ".tiff"},
                "GIF": {".gif"}, "RTF": {".rtf", ".doc"}}


def nome_per_contenuto(filename: str, dati: bytes) -> str:
    """Nome pulito con l'estensione giusta per il contenuto: "Determina n.123.p7m" con un PDF -> "Determina n.123.pdf"."""
    nome = pulisci_nome_file_globale(filename)
    tipo, ext_reale = sniff_contenuto(dati)
    ext = os.path.splitext(nome)[1].lower() if _estensione_vera(nome) else ""
    if ext_reale and ((tipo in _EST_DI_TIPO and ext not in _EST_DI_TIPO[tipo]) or not ext):
        nome += ext_reale
    return nome


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for blocco in iter(lambda: f.read(1 << 20), b''):
            h.update(blocco)
    return h.hexdigest()


def fmt_size(n: int) -> str:
    n = float(n or 0)
    for unita in ("B", "KB", "MB", "GB"):
        if n < 1024 or unita == "GB":
            return f"{n:.0f} {unita}" if unita == "B" else f"{n:.1f} {unita}"
        n /= 1024
    return "-"


def dt_locale(dt):
    if dt is None:
        return None
    try:
        return dt.astimezone()
    except Exception:
        return dt


def fmt_data(dt) -> str:
    d = dt_locale(dt)
    return d.strftime("%d/%m/%Y") if d else "N/D"


def fmt_ora(dt) -> str:
    d = dt_locale(dt)
    if not d:
        return "N/D"
    off = d.strftime("%z")
    sfx = f" (UTC{off[:3]}:{off[3:]})" if off else ""
    return d.strftime("%H:%M:%S") + sfx


def fmt_dt(dt) -> str:
    return f"{fmt_data(dt)} {fmt_ora(dt)}" if dt else "N/D"


def tronca(s: str, n: int) -> str:
    return s if len(s) <= n else s[:n - 1] + "…"


def data_italiana() -> str:
    mesi = ["GEN", "FEB", "MAR", "APR", "MAG", "GIU", "LUG", "AGO", "SET", "OTT", "NOV", "DIC"]
    giorni = ["LUNEDÌ", "MARTEDÌ", "MERCOLEDÌ", "GIOVEDÌ", "VENERDÌ", "SABATO", "DOMENICA"]
    o = datetime.datetime.now()
    return f"{giorni[o.weekday()]} {o.day} {mesi[o.month - 1]} {o.year}"


def parse_pdf_date(s) -> Optional[datetime.datetime]:
    """Converte una data PDF (D:YYYYMMDDHHmmSS+HH'mm') in datetime consapevole del fuso."""
    if not s:
        return None
    s = str(s).strip()
    if s.startswith("D:"):
        s = s[2:]
    m = re.match(r"(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:(Z)|([+\-])(\d{2})(?:'?(\d{2})'?)?)?", s)
    if not m:
        return None
    try:
        anno, mese, giorno, ore, minuti, sec = [int(x) if x else d for x, d in
                                                  zip(m.groups()[:6], (0, 1, 1, 0, 0, 0))]
        dt = datetime.datetime(anno, mese, giorno, ore, minuti, sec)
        if m.group(7):
            return dt.replace(tzinfo=datetime.timezone.utc)
        if m.group(8):
            delta = datetime.timedelta(hours=int(m.group(9)), minutes=int(m.group(10) or 0))
            return dt.replace(tzinfo=datetime.timezone(delta if m.group(8) == '+' else -delta))
        return dt.astimezone()          # fuso assente: si assume quello locale
    except Exception:
        return None


def parse_iso(s) -> Optional[datetime.datetime]:
    if not s:
        return None
    try:
        s2 = str(s).strip().replace('Z', '+00:00')
        s2 = re.sub(r'\.(\d+)', lambda m: '.' + (m.group(1) + '000000')[:6], s2)
        dt = datetime.datetime.fromisoformat(s2)
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None


def apri_con_sistema(path: str) -> bool:
    try:
        if sys.platform == "win32":
            os.startfile(path)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return True
    except Exception:
        return False


def mostra_in_cartella(path: str):
    try:
        if sys.platform == "win32":
            subprocess.Popen(["explorer", f"/select,{os.path.normpath(path)}"])
        else:
            apri_con_sistema(os.path.dirname(path))
    except Exception:
        pass


def _get(nome_obj, chiave: str) -> str:
    try:
        v = nome_obj.native.get(chiave)
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        return str(v) if v else ""
    except Exception:
        return ""


# ============================================================ MODELLO DATI
ORDINE_STATO = {"ok": 0, "none": 1, "warn": 2, "error": 3}


@dataclass
class Controllo:
    nome: str
    stato: str                        # ok / warn / error / none (solo informativo)
    dettaglio: str = ""


@dataclass
class FirmaInfo:
    tipo: str = "Firma"
    formato: str = ""
    livello: int = 0
    firmatario: str = "Sconosciuto"
    identificativo: str = ""
    organizzazione: str = ""
    emittente: str = ""
    seriale: str = ""
    data_firma: Optional[datetime.datetime] = None
    fonte_data: str = ""
    data_pdf_m: Optional[datetime.datetime] = None
    marca_temporale: Optional[datetime.datetime] = None
    marca_valida: Optional[bool] = None
    marca_tsa: str = ""
    valido_dal: Optional[datetime.datetime] = None
    valido_al: Optional[datetime.datetime] = None
    algo_hash: str = ""
    algo_firma: str = ""
    integrita: Optional[bool] = None
    integrita_msg: str = ""
    stato: str = "none"
    esito: str = ""
    note: List[str] = field(default_factory=list)
    controlli: List[Controllo] = field(default_factory=list)
    cert_der: Optional[bytes] = None
    campo: str = ""
    motivo: str = ""
    luogo: str = ""
    contatto: str = ""
    modifiche: str = ""
    mod_livello: str = ""


@dataclass
class RisultatoDoc:
    percorso: str
    nome: str = ""
    formato: str = "?"
    dimensione: int = 0
    sha256: str = ""
    firme: List[FirmaInfo] = field(default_factory=list)
    stato: str = "none"
    esito: str = ""
    errore: str = ""
    nome_contenuto: str = ""
    tipo_contenuto: str = ""
    livelli: int = 0
    fattura: Optional[dict] = None
    durata: float = 0.0
    verificato: bool = True
    note: List[str] = field(default_factory=list)
    estr_esito: str = ""              # ok / duplicato / permessi / errore
    estr_dettaglio: str = ""          # percorso di destinazione o messaggio di errore
    originale_eliminato: bool = False

    def finalizza(self):
        if self.errore:
            self.stato, self.esito = "error", self.errore
        elif not self.firme:
            self.stato, self.esito = "none", "Nessuna firma digitale presente"
        elif not self.verificato:
            self.stato, self.esito = "none", "Verifica non eseguita (solo estrazione)"
        else:
            peggiore = max(self.firme, key=lambda f: ORDINE_STATO.get(f.stato, 0))
            self.stato, self.esito = peggiore.stato, peggiore.esito


ETICHETTA = {"ok": "Verificato", "warn": "Attenzione", "error": "Non valido", "none": "Senza firma"}
ETICHETTA_ESTRAZIONE = {"ok": "Estratto", "duplicato": "Già presente", "permessi": "Permessi negati", "errore": "Fallito",
                        "": "—"}


def etichetta_doc(r: RisultatoDoc) -> str:
    return "Non verificato" if (r.stato == "none" and r.firme) else ETICHETTA[r.stato]


def etichetta_firma(f: FirmaInfo) -> str:
    return "Non verificata" if f.stato == "none" else ETICHETTA[f.stato]


# ============================================================ ARCHIVIO DI FIDUCIA
# Trusted List italiana (AgID, eIDAS): l'elenco ufficiale dei certificatori qualificati e' la fonte giusta per
# le radici delle firme. Si riscarica a ogni avvio (se c'e' connessione) e si tiene in cache; offline si usa
# l'ultima copia scaricata, altrimenti il TSL-IT.xml distribuito accanto al programma o incluso nell'exe.
URL_TSL = "https://eidas.agid.gov.it/TL/TSL-IT.xml"
_TSL_TIPI_FIDUCIA = {"CA/QC", "CA/PKC", "TSA/QTST", "TSA"}
_TSL_STATI_RITIRATI = {"withdrawn", "deprecatedatnationallevel"}


def _percorso_cache_tsl() -> str:
    return os.path.join(cartella_config(), "TSL-IT.xml")


def _percorsi_tsl_distribuita() -> List[str]:
    cartella = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
    return [os.path.join(c, "TSL-IT.xml") for c in (getattr(sys, '_MEIPASS', ''), cartella) if c]


def _tag_locale(tag) -> str:
    return tag.rsplit('}', 1)[-1] if isinstance(tag, str) else ""


def leggi_tsl(dati: bytes):
    """Certificati dei servizi CA/TSA della Trusted List: [(certificato, tipo servizio, data ritiro o None)], descrizione.
    Solleva un'eccezione se il file non e' una Trusted List con certificati (download troncato, pagina di errore...)."""
    radice = ET.fromstring(dati)
    if _tag_locale(radice.tag) != "TrustServiceStatusList":
        raise ValueError("non e' una Trusted List")
    numero = emessa = ""
    for e in radice.iter():
        nome = _tag_locale(e.tag)
        if nome == "TSLSequenceNumber" and not numero:
            numero = (e.text or "").strip()
        elif nome == "ListIssueDateTime" and not emessa:
            emessa = (e.text or "").strip()
    certificati = []
    for info in radice.iter():
        if _tag_locale(info.tag) != "ServiceInformation":
            continue
        tipo = stato = inizio = ""
        for c in info:
            nome = _tag_locale(c.tag)
            if nome == "ServiceTypeIdentifier":
                tipo = (c.text or "").strip().split("/Svctype/")[-1]
            elif nome == "ServiceStatus":
                stato = (c.text or "").strip().rsplit("/", 1)[-1]
            elif nome == "StatusStartingTime":
                inizio = (c.text or "").strip()
        if tipo not in _TSL_TIPI_FIDUCIA:
            continue
        ritiro = parse_iso(inizio) if stato in _TSL_STATI_RITIRATI else None
        for e in info.iter():
            if _tag_locale(e.tag) == "X509Certificate" and e.text:
                try:
                    certificati.append((x509.Certificate.load(base64.b64decode("".join(e.text.split()))), tipo, ritiro))
                except Exception:
                    pass
    if not certificati:
        raise ValueError("Trusted List senza certificati")
    d = parse_iso(emessa)
    return certificati, f"Trusted List AgID n. {numero or '?'} del {fmt_data(d) if d else emessa or '?'}"


def carica_tsl(online: bool):
    """Scarica la Trusted List AgID (e aggiorna la cache); senza rete, o con online=False, usa la cache
    o la copia distribuita."""
    cache = _percorso_cache_tsl()
    if online:
        try:
            req = urllib.request.Request(URL_TSL, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=20) as r:
                dati = r.read()
            certificati, descr = leggi_tsl(dati)
            try:
                os.makedirs(os.path.dirname(cache), exist_ok=True)
                with open(cache + ".tmp", "wb") as f:
                    f.write(dati)
                os.replace(cache + ".tmp", cache)
            except Exception:
                pass
            return certificati, descr + " (aggiornata online)"
        except Exception:
            pass
    motivo = "rete non disponibile" if online else "aggiornamento online in corso"
    for percorso, origine in [(cache, "copia in cache")] + [(p, "copia distribuita") for p in _percorsi_tsl_distribuita()]:
        try:
            with open(percorso, "rb") as f:
                certificati, descr = leggi_tsl(f.read())
            return certificati, f"{descr} ({origine}, {motivo})"
        except Exception:
            continue
    return [], "Trusted List AgID non disponibile (nessuna rete e nessuna copia locale)"


class ArchivioFiducia:
    """Radici attendibili: Trusted List AgID (eIDAS) + archivio di sistema + CA aggiunte dall'utente."""

    def __init__(self):
        self.lock = threading.Lock()
        self.radici: List[x509.Certificate] = []
        self.intermedi: List[x509.Certificate] = []
        self.hash_radici = set()
        self.tsl = {}                  # sha256 -> (tipo servizio, data ritiro o None) dei certificati della Trusted List
        self.tsl_descrizione = ""
        self._tsl_letta = None
        self.cache_http = {}
        self.cache_validazione = {}
        self._lock_chiavi = weakref.WeakKeyDictionary()
        self.ricarica()

    def lock_chiave(self, chiave):
        """Un lock asincrono per certificato: lo stesso firmatario su mille file si valida una volta sola."""
        # per ciclo asyncio (chiave debole): un lock legato a un ciclo chiuso non deve mai finire in uno nuovo
        locks = self._lock_chiavi.setdefault(asyncio.get_running_loop(), {})
        if chiave not in locks:
            locks[chiave] = asyncio.Lock()
        return locks[chiave]

    @staticmethod
    def _carica_file(percorso: str) -> List[x509.Certificate]:
        with open(percorso, 'rb') as f:
            dati = f.read()
        if b'-----BEGIN' in dati[:200]:
            return [x509.Certificate.load(der) for _, _, der in pem.unarmor(dati, multiple=True)]
        return [x509.Certificate.load(dati)]

    def ricarica(self, scarica_tsl: bool = False):
        """Ricostruisce l'archivio. La Trusted List si scarica solo con scarica_tsl (all'avvio, in sottofondo);
        altrimenti si riusa quella gia' letta o la copia locale, cosi' l'interfaccia non aspetta la rete."""
        radici, intermedi, tsl = [], [], {}
        if scarica_tsl or self._tsl_letta is None:
            self._tsl_letta = carica_tsl(online=scarica_tsl)
        certificati_tsl, descrizione_tsl = self._tsl_letta
        for c, tipo, ritiro in certificati_tsl:
            radici.append(c)
            tsl[hashlib.sha256(c.dump()).hexdigest()] = (tipo, ritiro)
        if sys.platform == "win32":
            for store, dest in (("ROOT", radici), ("CA", intermedi)):
                try:
                    for cert_bytes, encoding, _trust in ssl.enum_certificates(store):
                        if encoding == "x509_asn":
                            try:
                                dest.append(x509.Certificate.load(cert_bytes))
                            except Exception:
                                pass
                except Exception:
                    pass
        else:
            try:
                import certifi
                radici.extend(self._carica_file(certifi.where()))
            except Exception:
                pass
        for p in IMP["radici_extra"]:
            try:
                radici.extend(self._carica_file(p))
            except Exception:
                pass
        visti, finali = set(), []
        for c in radici:
            h = hashlib.sha256(c.dump()).hexdigest()
            if h not in visti:
                visti.add(h)
                finali.append(c)
        with self.lock:
            self.radici, self.intermedi = finali, intermedi
            self.hash_radici = visti
            self.tsl, self.tsl_descrizione = tsl, descrizione_tsl
            self.cache_validazione.clear()

    def ancora_tsl(self, cert, extra):
        """Primo certificato della catena (il firmatario escluso) presente nella Trusted List, o None."""
        corrente = cert
        for _ in range(8):
            nxt = self._cerca_emittente(corrente, list(extra) + self.intermedi + self.radici)
            if nxt is None:
                return None
            if hashlib.sha256(nxt.dump()).hexdigest() in self.tsl:
                return nxt
            if nxt.issuer == nxt.subject:
                return None
            corrente = nxt
        return None

    def scarica(self, url: str) -> Optional[bytes]:
        if url in self.cache_http:
            return self.cache_http[url]
        dati = None
        if url.lower().startswith(("http://", "https://")):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=6) as r:
                    dati = r.read()
            except Exception:
                dati = None
        self.cache_http[url] = dati
        return dati

    @staticmethod
    def _cerca_emittente(cert, pool):
        aki = None
        try:
            aki = cert.authority_key_identifier
        except Exception:
            pass
        for c in pool:
            try:
                if c.subject != cert.issuer and c.subject.dump() != cert.issuer.dump():
                    continue
                if aki and c.key_identifier and aki != c.key_identifier:
                    continue
                return c
            except Exception:
                continue
        return None

    def completa_catena(self, cert, extra_certs) -> List[x509.Certificate]:
        """Risale la catena usando busta, archivio di sistema e AIA. Restituisce i certificati utili."""
        trovati = list(extra_certs)
        corrente = cert
        for _ in range(6):
            if corrente.issuer == corrente.subject:
                break
            emittente = self._cerca_emittente(corrente, trovati + self.intermedi + self.radici)
            if emittente is not None:
                corrente = emittente
                continue
            nuovo = None
            try:
                aia = corrente.authority_information_access_value
            except Exception:
                aia = None
            for ad in (aia or []):
                try:
                    if ad['access_method'].native != 'ca_issuers':
                        continue
                    dati = self.scarica(ad['access_location'].native)
                    if not dati:
                        continue
                    try:
                        nuovo = x509.Certificate.load(dati)
                    except Exception:
                        sd = cms.ContentInfo.load(dati)['content']
                        cand = [c.chosen for c in sd['certificates'] if c.name == 'certificate']
                        nuovo = self._cerca_emittente(corrente, cand)
                    if nuovo is not None:
                        break
                except Exception:
                    continue
            if nuovo is None:
                break
            trovati.append(nuovo)
            corrente = nuovo
        return trovati

    def radice_catena(self, cert, extra):
        corrente = cert
        for _ in range(8):
            if corrente.issuer == corrente.subject:
                return corrente
            nxt = self._cerca_emittente(corrente, list(extra) + self.intermedi + self.radici)
            if nxt is None:
                return None
            corrente = nxt
        return None


ARCHIVIO = ArchivioFiducia()


# ============================================================ MOTORE: CMS / CERTIFICATI
def carica_cms(raw: bytes, consenti_b64: bool = False):
    if raw[:1] != b'\x30':
        try:
            testa = raw.lstrip()
            if testa.startswith(b'-----BEGIN'):
                _, _, raw = pem.unarmor(testa)
            elif consenti_b64:
                raw = base64.b64decode(b''.join(raw.split()), validate=True)
        except Exception:
            pass
    return cms.ContentInfo.load(raw)


def e_busta_cms(raw: bytes):
    try:
        info = carica_cms(raw, raw.lstrip()[:1] == b'M')       # le buste base64 iniziano sempre per "M"
        return info if info['content_type'].native == 'signed_data' else None
    except Exception:
        return None


def byte_ottetti(v) -> bytes:
    """Byte di un OCTET STRING, anche costruito o a lunghezza indefinita."""
    try:
        return v.__bytes__()
    except Exception:
        return v.contents


def certificati_da_sd(sd) -> List[x509.Certificate]:
    try:
        campo = sd['certificates']
        if isinstance(campo, Void):
            return []
        return [c.chosen for c in campo if c.name == 'certificate']
    except Exception:
        return []


def _stessi_nomi(a, b) -> bool:
    try:
        return a == b or a.dump() == b.dump()
    except Exception:
        return False


def trova_cert_signer(signer_info, certs):
    try:
        sid = signer_info['sid']
        if sid.name == 'issuer_and_serial_number':
            emittente = sid.chosen['issuer']
            seriale = sid.chosen['serial_number'].native
            for c in certs:
                if c.serial_number == seriale and _stessi_nomi(c.issuer, emittente):
                    return c
            for c in certs:
                if c.serial_number == seriale:
                    return c
        elif sid.name == 'subject_key_identifier':
            ski = sid.chosen.native
            for c in certs:
                if c.key_identifier == ski:
                    return c
    except Exception:
        pass
    return None


def gen_time_da_eci(eci):
    try:
        return tsp.TSTInfo.load(byte_ottetti(eci['content']))['gen_time'].native
    except Exception:
        return None


def estrai_tempi(signer_info):
    """(signing_time dichiarato, gen_time della marca temporale)"""
    st = marca = None
    try:
        sa = signer_info['signed_attrs']
        if not isinstance(sa, Void):
            for a in sa:
                if a['type'].native == 'signing_time':
                    st = a['values'][0].native
                    break
    except Exception:
        pass
    try:
        ua = signer_info['unsigned_attrs']
        if not isinstance(ua, Void):
            for a in ua:
                if a['type'].dotted == OID_TIMESTAMP_TOKEN:
                    tok = a['values'][0]
                    marca = gen_time_da_eci(tok['content']['encap_content_info'])
                    break
    except Exception:
        pass
    return st, marca


def controfirme(signer_info):
    out = []
    try:
        ua = signer_info['unsigned_attrs']
        if not isinstance(ua, Void):
            for a in ua:
                if a['type'].dotted == OID_COUNTER_SIGNATURE:
                    out.extend(list(a['values']))
    except Exception:
        pass
    return out


def algoritmi(signer_info) -> Tuple[str, str]:
    h = s = ""
    try:
        h = signer_info['digest_algorithm']['algorithm'].native
    except Exception:
        pass
    try:
        s = signer_info['signature_algorithm'].signature_algo
    except Exception:
        try:
            s = signer_info['signature_algorithm']['algorithm'].native
        except Exception:
            pass
    return str(h), str(s)


_HASH_CLASSI = ({'sha1': hashes.SHA1, 'sha224': hashes.SHA224, 'sha256': hashes.SHA256, 'sha384': hashes.SHA384,
                 'sha512': hashes.SHA512, 'sha3_224': hashes.SHA3_224, 'sha3_256': hashes.SHA3_256,
                 'sha3_384': hashes.SHA3_384, 'sha3_512': hashes.SHA3_512} if HAS_CRYPTO else {})


def _verifica_firma_grezza(chiave, firma: bytes, dati: bytes, sig_algo, classe_hash):
    tipo = sig_algo.signature_algo
    try:
        classe_h = _HASH_CLASSI.get(sig_algo.hash_algo, classe_hash)
    except Exception:
        classe_h = classe_hash
    if tipo == 'rsassa_pkcs1v15':
        chiave.verify(firma, dati, padding.PKCS1v15(), classe_h())
    elif tipo == 'rsassa_pss':
        p = sig_algo['parameters']
        h_pss = _HASH_CLASSI.get(p['hash_algorithm']['algorithm'].native, classe_h)
        h_mgf = _HASH_CLASSI.get(p['mask_gen_algorithm']['parameters']['algorithm'].native, h_pss)
        chiave.verify(firma, dati, padding.PSS(mgf=padding.MGF1(h_mgf()), salt_length=p['salt_length'].native), h_pss())
    elif tipo == 'ecdsa':
        chiave.verify(firma, dati, ec.ECDSA(classe_h()))
    elif tipo == 'dsa':
        chiave.verify(firma, dati, classe_h())
    elif tipo in ('ed25519', 'ed448'):
        chiave.verify(firma, dati)
    else:
        raise NotImplementedError(tipo)


def verifica_integrita(signer_info, cert, payload: Optional[bytes]) -> Tuple[Optional[bool], str]:
    """Controlla digest del contenuto e firma. (True/False/None, messaggio)"""
    if not HAS_CRYPTO:
        return None, "libreria 'cryptography' non disponibile"
    if payload is None:
        return None, "firma detached: documento originale non disponibile"
    try:
        algo = signer_info['digest_algorithm']['algorithm'].native
        classe_hash = _HASH_CLASSI.get(algo)
        if classe_hash is None:
            return None, f"algoritmo di digest '{algo}' non supportato"
        sa = signer_info['signed_attrs']
        if isinstance(sa, Void):
            candidati = [payload]
        else:
            md = None
            for a in sa:
                if a['type'].native == 'message_digest':
                    md = a['values'][0].native
                    break
            if md is None:
                return False, "attributo message-digest mancante"
            if hashlib.new(algo, payload).digest() != md:
                return False, "l'impronta del contenuto non corrisponde: documento alterato dopo la firma"
            # prima la codifica originale (alcuni software non ordinano il SET), poi quella DER canonica
            candidati = [b'\x31' + sa.dump()[1:]]
            canonica = b'\x31' + sa.dump(force=True)[1:]
            if canonica != candidati[0]:
                candidati.append(canonica)
        firma = signer_info['signature'].native
        chiave = serialization.load_der_public_key(cert['tbs_certificate']['subject_public_key_info'].dump())
        for dati in candidati:
            try:
                _verifica_firma_grezza(chiave, firma, dati, signer_info['signature_algorithm'], classe_hash)
                return True, "impronta e firma crittografica verificate: documento integro"
            except InvalidSignature:
                continue
        return False, "firma crittografica non valida: documento alterato o firma corrotta"
    except NotImplementedError as e:
        return None, f"algoritmo di firma '{e}' non supportato"
    except Exception as e:
        return None, f"verifica non eseguibile ({type(e).__name__})"


def verifica_legame_certificato(signer_info, cert) -> Controllo:
    """Attributo ESS signing-certificate: lega la firma proprio a quel certificato."""
    nome = "Legame firma-certificato"
    try:
        sa = signer_info['signed_attrs']
        if not isinstance(sa, Void):
            for a in sa:
                t = a['type'].native
                if t in ('signing_certificate', 'signing_certificate_v2'):
                    primo = a['values'][0]['certs'][0]
                    algo = 'sha1' if t == 'signing_certificate' else primo['hash_algorithm']['algorithm'].native
                    if hashlib.new(algo, cert.dump()).digest() == primo['cert_hash'].native:
                        return Controllo(nome, "ok", "l'attributo signing-certificate corrisponde al certificato usato")
                    return Controllo(nome, "error", "l'attributo signing-certificate indica un certificato diverso da quello usato")
    except Exception as e:
        return Controllo(nome, "none", f"attributo non leggibile ({type(e).__name__})")
    return Controllo(nome, "none", "attributo signing-certificate assente")


def token_marca(signer_info):
    try:
        ua = signer_info['unsigned_attrs']
        if not isinstance(ua, Void):
            for a in ua:
                if a['type'].dotted == OID_TIMESTAMP_TOKEN:
                    return a['values'][0]
    except Exception:
        pass
    return None


async def verifica_marca(token, dati_marcati: Optional[bytes]) -> Tuple[Optional[bool], Optional[datetime.datetime], str, str]:
    """Verifica una marca RFC 3161: impronta dei dati marcati, firma del token, certificato TSA.
    -> (valida, istante, TSA, spiegazione)"""
    quando, tsa = None, ""
    try:
        sd = token['content']
        eci = sd['encap_content_info']
        contenuto = byte_ottetti(eci['content'])
        info = tsp.TSTInfo.load(contenuto)
        quando = info['gen_time'].native
        imprint = info['message_imprint']
        algo = imprint['hash_algorithm']['algorithm'].native
        if dati_marcati is not None and hashlib.new(algo, dati_marcati).digest() != imprint['hashed_message'].native:
            return False, quando, tsa, "l'impronta della marca non corrisponde alla firma: marca non valida"
        si = sd['signer_infos'][0]
        certs = certificati_da_sd(sd)
        cert = trova_cert_signer(si, certs)
        if cert is None:
            return None, quando, tsa, "certificato della TSA non incluso nella marca"
        tsa = _get(cert.subject, 'common_name') or _get(cert.subject, 'organization_name')
        integra, msg = verifica_integrita(si, cert, contenuto)
        if integra is False:
            return False, quando, tsa, f"firma della marca non valida ({msg})"
        if integra is None:
            return None, quando, tsa, f"firma della marca non verificabile ({msg})"
        controlli = await valida_certificato(cert, certs, quando, tsa=True)
        peggiore = next((c for c in controlli if c.stato == "error"), None)
        if peggiore is not None:
            return False, quando, tsa, f"certificato TSA non attendibile: {peggiore.dettaglio}"
        return True, quando, tsa, f"marca valida emessa da {tsa or 'TSA'} il {fmt_dt(quando)}"
    except Exception as e:
        return None, quando, tsa, f"marca non verificabile ({type(e).__name__})"


def popola_da_cert(fi: FirmaInfo, cert: x509.Certificate):
    fi.cert_der = cert.dump()
    cn = _get(cert.subject, 'common_name')
    nome = " ".join(x for x in (_get(cert.subject, 'given_name'), _get(cert.subject, 'surname')) if x)
    fi.organizzazione = _get(cert.subject, 'organization_name')
    fi.firmatario = cn or nome or fi.organizzazione or "Sconosciuto"
    fi.identificativo = _get(cert.subject, 'serial_number')
    fi.emittente = _get(cert.issuer, 'common_name') or _get(cert.issuer, 'organization_name')
    fi.seriale = format(cert.serial_number, 'X')
    try:
        fi.valido_dal = cert['tbs_certificate']['validity']['not_before'].native
        fi.valido_al = cert['tbs_certificate']['validity']['not_after'].native
    except Exception:
        pass


_QC_CONFORME = bytes.fromhex("0606040 08E460101".replace(" ", ""))
_QC_QSCD = bytes.fromhex("0606040 08E460104".replace(" ", ""))


def controllo_tipo_certificato(cert) -> Controllo:
    der = cert.dump()
    if _QC_CONFORME in der:
        testo = "certificato qualificato" + (" su dispositivo sicuro (QSCD)" if _QC_QSCD in der else "")
    else:
        testo = "certificato non dichiarato come qualificato"
    try:
        ku = cert.key_usage_value
        if ku is not None and 'non_repudiation' in ku.native:
            testo += ", abilitato alla non ripudiabilità"
    except Exception:
        pass
    return Controllo("Tipo di certificato", "none", testo)


def controllo_algoritmi(fi: FirmaInfo, cert) -> Controllo:
    deboli = []
    if fi.algo_hash.lower() in ('md5', 'md2', 'sha1'):
        deboli.append(f"impronta {fi.algo_hash.upper()}")
    try:
        if cert.public_key.algorithm == 'rsa' and cert.public_key.bit_size < 2048:
            deboli.append(f"chiave RSA a {cert.public_key.bit_size} bit")
    except Exception:
        pass
    testo = " / ".join(x for x in (fi.algo_hash, fi.algo_firma) if x)
    if deboli:
        return Controllo("Algoritmi", "warn", "algoritmi oggi considerati deboli: " + ", ".join(deboli))
    return Controllo("Algoritmi", "ok", testo or "non indicati")


def controllo_tempi(fi: FirmaInfo) -> Optional[Controllo]:
    d = fi.data_firma
    if not d or fi.marca_valida:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    if d > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5):
        return Controllo("Data di firma", "warn", f"la data dichiarata ({fmt_dt(d)}) è nel futuro")
    if fi.valido_dal and d < fi.valido_dal:
        return Controllo("Data di firma", "warn", f"la data dichiarata ({fmt_dt(d)}) precede l'inizio di validità del certificato")
    if fi.valido_al and d > fi.valido_al:
        return Controllo("Data di firma", "warn", f"la data dichiarata ({fmt_dt(d)}) è successiva alla scadenza del certificato")
    return None


async def _valida_cert_reale(cert, certs_busta, momento_firma, moment, marca, tsa) -> List[Controllo]:
    c: List[Controllo] = []
    ora = datetime.datetime.now(datetime.timezone.utc)
    try:
        nb = cert['tbs_certificate']['validity']['not_before'].native
        na = cert['tbs_certificate']['validity']['not_after'].native
    except Exception:
        nb = na = None
    scaduto = bool(na and na < ora)
    futuro = bool(nb and nb > ora)
    revoca_attiva = bool(IMP["revoca"])
    extra = await asyncio.to_thread(ARCHIVIO.completa_catena, cert, list(certs_busta))
    ctx = ValidationContext(trust_roots=list(ARCHIVIO.radici), other_certs=list(ARCHIVIO.intermedi) + extra,
                            allow_fetching=revoca_attiva, revocation_mode="soft-fail", moment=moment,
                            # a una data passata OCSP/CRL sono per forza successive: vanno accettate lo stesso
                            retroactive_revinfo=bool(moment))
    try:
        validatore = CertificateValidator(cert, validation_context=ctx)
        if tsa:
            await validatore.async_validate_usage(set(), extended_key_usage={'time_stamping'})
        else:
            await validatore.async_validate_usage(set())
    except Exception as e:
        nome_err = type(e).__name__
        msg = (str(e).strip().splitlines() or [nome_err])[0]
        if 'Revoked' in nome_err:
            quando = getattr(e, 'revocation_dt', None)
            motivo = getattr(getattr(e, 'reason', None), 'human_friendly', '')
            c.append(Controllo("Revoca", "error", "certificato REVOCATO" + (f" il {fmt_dt(quando)}" if quando else "")
                               + (f" ({motivo})" if motivo else "")))
        elif futuro:
            c.append(Controllo("Validità del certificato", "error", f"non ancora valido (dal {fmt_data(nb)})"))
        elif 'Expired' in nome_err or (scaduto and not moment):
            c.append(Controllo("Validità del certificato", "error", f"scaduto il {fmt_data(na)}, nessuna data utile per valutarlo"))
        elif isinstance(e, PathValidationError) or 'PathBuilding' in nome_err or 'Validation' in nome_err:
            radice = ARCHIVIO.radice_catena(cert, extra)
            if radice is not None and hashlib.sha256(radice.dump()).hexdigest() not in ARCHIVIO.hash_radici:
                nome_radice = _get(radice.subject, 'common_name') or _get(radice.subject, 'organization_name')
                c.append(Controllo("Catena di fiducia", "warn", f"catena completa fino a «{nome_radice}», radice non presente "
                                   "tra quelle attendibili (si può aggiungere in Impostazioni)"))
            else:
                emittente = _get(cert.issuer, 'common_name') or _get(cert.issuer, 'organization_name') or "sconosciuto"
                if 'PathBuilding' in nome_err:
                    c.append(Controllo("Catena di fiducia", "error", f"l'emittente «{emittente}» non è tra le autorità attendibili "
                                       "(Trusted List AgID, archivio di Windows, CA aggiunte)"))
                else:
                    c.append(Controllo("Catena di fiducia", "error", f"non verificata: {msg}"))
        else:
            c.append(Controllo("Validazione del certificato", "warn", f"verifica parziale: {msg}"))
        return c
    finally:
        try:
            await ctx.aclose()
        except Exception:
            pass

    periodo = f"dal {fmt_data(nb)} al {fmt_data(na)}"
    if tsa:
        c.append(Controllo("Validità del certificato", "ok", f"valido al momento della marca ({periodo})"))
    elif moment and marca:
        c.append(Controllo("Validità del certificato", "ok", f"valido alla data della marca temporale, {fmt_dt(moment)} ({periodo})"))
    elif moment:
        c.append(Controllo("Validità del certificato", "warn", f"scaduto il {fmt_data(na)}: valido solo alla data di firma "
                           "dichiarata dal firmatario, senza marca temporale opponibile"))
    else:
        c.append(Controllo("Validità del certificato", "ok", f"in corso di validità ({periodo})"))
    ancora = ARCHIVIO.ancora_tsl(cert, extra)
    if ancora is not None:
        tipo, ritiro = ARCHIVIO.tsl[hashlib.sha256(ancora.dump()).hexdigest()]
        nome_ca = _get(ancora.subject, 'common_name') or _get(ancora.subject, 'organization_name')
        quando = moment or momento_firma or ora
        if quando.tzinfo is None:
            quando = quando.replace(tzinfo=datetime.timezone.utc)
        c.append(Controllo("Catena di fiducia", "ok", f"verificata fino a «{nome_ca}»"))
        if ritiro and quando >= ritiro:
            c.append(Controllo("Trusted List AgID", "warn", f"certificatore «{nome_ca}» ritirato dalla lista il {fmt_data(ritiro)}, prima della firma"))
        else:
            c.append(Controllo("Trusted List AgID", "ok", f"certificatore qualificato eIDAS ({tipo})"))
    else:
        c.append(Controllo("Catena di fiducia", "ok", "verificata sull'archivio di Windows o sulle CA aggiunte"))
        c.append(Controllo("Trusted List AgID", "none", "certificatore non presente nella lista"))
    if not revoca_attiva:
        c.append(Controllo("Revoca", "none", "controllo OCSP/CRL disattivato nelle impostazioni"))
    else:
        try:
            mancate = list(ctx.soft_fail_exceptions)
        except Exception:
            mancate = []
        if mancate:
            c.append(Controllo("Revoca", "warn", "stato non determinabile: server OCSP/CRL non raggiungibili o senza risposta utile"))
        else:
            c.append(Controllo("Revoca", "ok", "nessuna revoca risultante da OCSP/CRL"))
    return c


async def valida_certificato(cert, certs_busta, momento_firma, marca=None, tsa=False) -> List[Controllo]:
    """Elenco dei controlli sul certificato. marca: istante di una marca GIA' verificata; tsa: certificato di una TSA."""
    ora = datetime.datetime.now(datetime.timezone.utc)
    try:
        scaduto = cert['tbs_certificate']['validity']['not_after'].native < ora
    except Exception:
        scaduto = False
    if tsa:
        moment = momento_firma
    elif marca:
        moment = marca                      # data certa: revoche e scadenze successive non contano
    elif scaduto and momento_firma and IMP["valida_data_firma"]:
        moment = momento_firma
    else:
        moment = None
    chiave = (hashlib.sha256(cert.dump()).hexdigest(), moment.isoformat() if moment else "", bool(IMP["revoca"]), bool(marca), tsa)
    async with ARCHIVIO.lock_chiave(chiave):
        if chiave in ARCHIVIO.cache_validazione:
            return list(ARCHIVIO.cache_validazione[chiave])
        controlli = await _valida_cert_reale(cert, certs_busta, momento_firma, moment, marca, tsa)
        if len(ARCHIVIO.cache_validazione) > 3000:
            ARCHIVIO.cache_validazione.clear()
        ARCHIVIO.cache_validazione[chiave] = list(controlli)
    return controlli


def controllo_integrita(fi: FirmaInfo) -> Controllo:
    return Controllo("Integrità del documento", {True: "ok", False: "error", None: "warn"}[fi.integrita],
                     fi.integrita_msg or "non verificata")


def controllo_marca(fi: FirmaInfo, msg: str) -> Controllo:
    if fi.marca_temporale is None and not msg:
        return Controllo("Marca temporale", "none", "assente: la data di firma è solo dichiarata")
    return Controllo("Marca temporale", {True: "ok", False: "warn", None: "warn"}[fi.marca_valida], msg)


def combina_esito(fi: FirmaInfo):
    """L'esito della firma e' il primo controllo peggiore: cosi' la tabella dice sempre il motivo."""
    for s in ("error", "warn"):
        c = next((x for x in fi.controlli if x.stato == s), None)
        if c is not None:
            fi.stato, fi.esito = s, f"{c.nome}: {c.dettaglio}"
            return
    fi.stato = "ok"
    fi.esito = "Firma valida: integrità, certificato e catena di fiducia verificati"


# ============================================================ MOTORE: CAdES
async def _analizza_signer(si, certs, payload, livello, tipo="Firma", formato="CAdES", valida=True) -> FirmaInfo:
    fi = FirmaInfo(tipo=tipo, formato=formato, livello=livello)
    fi.algo_hash, fi.algo_firma = algoritmi(si)
    st, marca = estrai_tempi(si)
    if st:
        fi.data_firma, fi.fonte_data = st, "Attributo signing-time della firma"
    fi.marca_temporale = marca
    if marca and not fi.data_firma:
        fi.data_firma, fi.fonte_data = marca, "Marca temporale (RFC 3161)"
    cert = trova_cert_signer(si, certs)
    if cert is None:
        fi.stato, fi.esito = "error", "Certificato del firmatario non presente nella busta"
        fi.controlli.append(Controllo("Certificato", "error", "non presente nella busta"))
        return fi
    popola_da_cert(fi, cert)
    if not valida:
        fi.esito = "Verifica non eseguita (solo estrazione)"
        return fi
    fi.integrita, fi.integrita_msg = verifica_integrita(si, cert, payload)
    fi.controlli.append(controllo_integrita(fi))
    fi.controlli.append(verifica_legame_certificato(si, cert))
    msg_marca = ""
    token = token_marca(si)
    if token is not None:
        fi.marca_valida, istante, fi.marca_tsa, msg_marca = await verifica_marca(token, si['signature'].native)
        fi.marca_temporale = istante or fi.marca_temporale
    fi.controlli.append(controllo_marca(fi, msg_marca))
    fi.controlli += await valida_certificato(cert, certs, fi.data_firma, fi.marca_temporale if fi.marca_valida else None)
    fi.controlli.append(controllo_algoritmi(fi, cert))
    fi.controlli.append(controllo_tipo_certificato(cert))
    t = controllo_tempi(fi)
    if t is not None:
        fi.controlli.append(t)
    combina_esito(fi)
    return fi


async def _firma_con_controfirme(si, certs, payload, livello, tipo, valida, prof=0) -> List[FirmaInfo]:
    out = [await _analizza_signer(si, certs, payload, livello, tipo=tipo, valida=valida)]
    if prof < 4:
        for ctr in controfirme(si):              # la controfirma firma il valore della firma madre
            out += await _firma_con_controfirme(ctr, certs, si['signature'].native, livello, "Controfirma", valida, prof + 1)
    return out


async def analizza_signed_data(sd, payload, livello, valida=True) -> List[FirmaInfo]:
    certs = certificati_da_sd(sd)
    out = []
    for si in sd['signer_infos']:
        out += await _firma_con_controfirme(si, certs, payload, livello, "Firma", valida)
    return out


def trova_originale_detached(percorso: str) -> Optional[str]:
    """Per una firma detached cerca accanto il file firmato: "doc.pdf.p7s" -> "doc.pdf"."""
    cartella, nome = os.path.split(percorso)
    candidato = pulisci_nome_file_globale(nome)
    p = os.path.join(cartella, candidato)
    if candidato != nome and os.path.isfile(p):
        return p
    return None


async def analizza_p7m(ris: RisultatoDoc, valida: bool = True):
    with open(ris.percorso, 'rb') as f:
        contenuto = f.read()
    livello = 0
    payload_bytes = None
    while True:
        try:
            info = carica_cms(contenuto, consenti_b64=(contenuto.lstrip()[:1] == b'M'))
        except Exception:
            ris.errore = "Decodifica fallita: il file non è una busta CMS/PKCS#7 valida"
            return
        if info['content_type'].native != 'signed_data':
            ris.errore = "Busta corrotta: tipo CMS diverso da SignedData"
            return
        sd = info['content']
        payload = sd['encap_content_info']['content']
        payload_bytes = None if isinstance(payload, Void) else byte_ottetti(payload)
        detached = payload_bytes is None
        if detached:
            originale = trova_originale_detached(ris.percorso)
            if originale:
                with open(originale, 'rb') as f:
                    payload_bytes = f.read()
                ris.note.append(f"Firma detached verificata sul file accanto: {os.path.basename(originale)}")
            else:
                ris.note.append("Firma detached: il documento firmato non è incluso e non è stato trovato accanto")
        ris.firme.extend(await analizza_signed_data(sd, payload_bytes, livello, valida))
        if not detached and payload_bytes and livello < MAX_ANNIDAMENTO and IMP["estrai_annidati"] and e_busta_cms(payload_bytes):
            contenuto = payload_bytes
            livello += 1
            ris.livelli = livello
            continue
        break
    ris.nome_contenuto = pulisci_nome_file_globale(ris.nome)
    if payload_bytes:
        ris.tipo_contenuto = sniff_contenuto(payload_bytes)[0]
        ris.nome_contenuto = nome_per_contenuto(ris.nome, payload_bytes)
        if ris.tipo_contenuto == "XML" and len(payload_bytes) < 30_000_000:
            ris.fattura = riepilogo_fattura(payload_bytes)


def leggi_contenuto_p7m(path: str) -> bytes:
    with open(path, 'rb') as f:
        dati = f.read()
    livello = 0
    while True:
        info = carica_cms(dati, dati.lstrip()[:1] == b'M')
        if info['content_type'].native != 'signed_data':
            raise ValueError("busta non valida")
        payload = info['content']['encap_content_info']['content']
        if isinstance(payload, Void):
            raise ValueError("contenuto assente (firma detached)")
        dati = byte_ottetti(payload)
        if not dati:
            raise ValueError("contenuto vuoto")
        if IMP["estrai_annidati"] and livello < MAX_ANNIDAMENTO and e_busta_cms(dati):
            livello += 1
            continue
        return dati


_LOCK_ESTRAZIONE = threading.Lock()


def estrai_p7m_su_disco(path: str, cartella_out: Optional[str] = None) -> Tuple[str, str]:
    """-> ('ok'|'duplicato'|'permessi'|'errore', percorso o messaggio).
    A parita' di nome pulito: stesso contenuto = gia' presente, contenuto diverso = "doc (2).pdf"."""
    try:
        dati = leggi_contenuto_p7m(path)
        nome = nome_per_contenuto(os.path.basename(path), dati)
        dest_dir = cartella_out or os.path.dirname(path)
        os.makedirs(dest_dir, exist_ok=True)
        impronta = hashlib.sha256(dati).hexdigest()
        base, ext = os.path.splitext(nome)
        with _LOCK_ESTRAZIONE:
            dest, n = os.path.join(dest_dir, nome), 2
            while os.path.exists(dest):
                if os.path.getsize(dest) == len(dati) and sha256_file(dest) == impronta:
                    return "duplicato", dest
                dest, n = os.path.join(dest_dir, f"{base} ({n}){ext}"), n + 1
            tmp = dest + ".part"
            with open(tmp, 'wb') as f:
                f.write(dati)
            os.replace(tmp, dest)
        return "ok", dest
    except PermissionError as e:
        return "permessi", str(e)
    except Exception as e:
        return "errore", f"{type(e).__name__}: {e}"


# ============================================================ MOTORE: PAdES
def _pdf_val(obj, chiave: str) -> str:
    try:
        v = obj[chiave]
        return str(v) if v is not None else ""
    except Exception:
        return ""


def descrivi_modifiche(status) -> Tuple[str, str]:
    dr = getattr(status, 'diff_result', None)
    cov = getattr(getattr(status, 'coverage', None), 'name', None)
    if dr is not None and type(dr).__name__ == 'SuspiciousModification':
        return "error", "Il documento risulta MODIFICATO dopo la firma"
    lvl = getattr(getattr(status, 'modification_level', None), 'name', None)
    if cov == 'ENTIRE_FILE':
        return "ok", "La firma copre l'intero file: documento non modificato dopo la firma"
    if cov == 'ENTIRE_REVISION':
        if lvl in (None, 'NONE'):
            return "ok", "Documento non modificato dopo la firma"
        if lvl in ('LTA_UPDATES', 'FORM_FILLING', 'ANNOTATIONS'):
            etichette = {'LTA_UPDATES': "aggiornamenti di validazione a lungo termine",
                         'FORM_FILLING': "compilazione di moduli", 'ANNOTATIONS': "annotazioni"}
            return "warn", f"Dopo la firma sono state aggiunte modifiche consentite ({etichette[lvl]})"
        return "error", "Il documento risulta MODIFICATO dopo la firma"
    if cov:
        return "warn", f"La firma non copre l'intero file (copertura: {cov.lower().replace('_', ' ')})"
    return "", ""


async def _firma_pdf(sig, valida=True) -> FirmaInfo:
    fi = FirmaInfo(formato="PAdES")
    obj = sig.sig_object
    is_ts = 'DocTimeStamp' in str(getattr(sig, 'sig_object_type', ''))
    fi.tipo = "Marca temporale del documento" if is_ts else "Firma"
    fi.campo = str(getattr(sig, 'field_name', '') or '')
    fi.motivo, fi.luogo = _pdf_val(obj, '/Reason'), _pdf_val(obj, '/Location')
    fi.contatto = _pdf_val(obj, '/ContactInfo')
    sd = sig.signed_data
    certs = certificati_da_sd(sd)
    si = sd['signer_infos'][0]
    fi.algo_hash, fi.algo_firma = algoritmi(si)
    st, marca = estrai_tempi(si)
    if is_ts:
        marca = gen_time_da_eci(sd['encap_content_info']) or marca
    try:
        attr = getattr(sig, 'self_reported_timestamp', None) or st
    except Exception:
        attr = st
    m = parse_pdf_date(_pdf_val(obj, '/M'))
    fi.data_pdf_m, fi.marca_temporale = m, marca
    if is_ts and marca:
        fi.data_firma, fi.fonte_data = marca, "Marca temporale (RFC 3161)"
    elif attr:
        fi.data_firma, fi.fonte_data = attr, "Attributo signing-time della firma"
    elif m:
        fi.data_firma, fi.fonte_data = m, "Data /M del dizionario di firma PDF"
    elif marca:
        fi.data_firma, fi.fonte_data = marca, "Marca temporale (RFC 3161)"
    if attr and m and abs((attr - m).total_seconds()) > 300:
        fi.note.append("La data /M del PDF differisce dall'attributo signing-time di oltre 5 minuti")
    cert = trova_cert_signer(si, certs)
    if cert is not None:
        popola_da_cert(fi, cert)
    if not valida:
        fi.esito = "Verifica non eseguita (solo estrazione)"
        return fi

    # integrita' (digest + firma + analisi modifiche) tramite pyHanko; la fiducia si valuta a parte
    ctx_vuoto = ValidationContext(trust_roots=[], allow_fetching=False)
    try:
        if is_ts and async_validate_pdf_timestamp:
            status = await async_validate_pdf_timestamp(sig, validation_context=ctx_vuoto)
        elif async_validate_pdf_signature:
            status = await async_validate_pdf_signature(sig, signer_validation_context=ctx_vuoto)
        elif validate_pdf_signature:
            status = await asyncio.to_thread(validate_pdf_signature, sig)
        else:
            status = None
        if status is not None:
            fi.integrita = bool(status.intact and status.valid)
            fi.integrita_msg = ("impronta e firma crittografica verificate" if fi.integrita
                                else "impronta o firma crittografica non valide: documento alterato o firma corrotta")
            fi.mod_livello, fi.modifiche = descrivi_modifiche(status)
        else:
            fi.integrita_msg = "motore di verifica PDF non disponibile"
    except Exception as e:
        fi.integrita, fi.integrita_msg = None, f"verifica non eseguibile ({type(e).__name__})"
    fi.controlli.append(controllo_integrita(fi))
    if fi.modifiche:
        fi.controlli.append(Controllo("Modifiche dopo la firma", fi.mod_livello or "none", fi.modifiche))

    if cert is None:
        fi.controlli.append(Controllo("Certificato", "error", "non presente nella firma"))
        combina_esito(fi)
        return fi
    msg_marca = ""
    if is_ts:
        fi.marca_valida = fi.integrita
        msg_marca = f"marca del documento: {fi.integrita_msg}"
    else:
        fi.controlli.append(verifica_legame_certificato(si, cert))
        token = token_marca(si)
        if token is not None:
            fi.marca_valida, istante, fi.marca_tsa, msg_marca = await verifica_marca(token, si['signature'].native)
            fi.marca_temporale = istante or fi.marca_temporale
    fi.controlli.append(controllo_marca(fi, msg_marca))
    if is_ts:
        fi.controlli += await valida_certificato(cert, certs, fi.data_firma, tsa=True)
    else:
        fi.controlli += await valida_certificato(cert, certs, fi.data_firma, fi.marca_temporale if fi.marca_valida else None)
    fi.controlli.append(controllo_algoritmi(fi, cert))
    if not is_ts:
        fi.controlli.append(controllo_tipo_certificato(cert))
        t = controllo_tempi(fi)
        if t is not None:
            fi.controlli.append(t)
    combina_esito(fi)
    return fi


def _apri_pdf(f):
    """Prima lettura rigorosa, poi tollerante (molti PDF reali hanno piccoli difetti). I PDF cifrati senza password si aprono."""
    ultimo = None
    for rigoroso in (True, False):
        try:
            f.seek(0)
            reader = PdfFileReader(f, strict=rigoroso)
            if reader.encrypted:
                reader.decrypt("")
            return list(reader.embedded_signatures)
        except Exception as e:
            ultimo = e
    raise ultimo


async def analizza_pdf(ris: RisultatoDoc, valida: bool = True):
    with open(ris.percorso, 'rb') as f:
        try:
            sigs = _apri_pdf(f)
        except Exception as e:
            ris.errore = f"PDF non leggibile o protetto da password ({type(e).__name__})"
            return
        for sig in sigs:
            try:
                ris.firme.append(await _firma_pdf(sig, valida))
            except Exception as e:
                ris.firme.append(FirmaInfo(formato="PAdES", stato="error",
                                           esito=f"Errore di lettura della firma ({type(e).__name__}: {e})"))


# ============================================================ MOTORE: XAdES + FatturaPA
def _loc(tag) -> str:
    return tag.rsplit('}', 1)[-1] if isinstance(tag, str) else ""


def _figlio(el, nome):
    for c in el:
        if _loc(c.tag) == nome:
            return c
    return None


def _percorso(el, *nomi) -> str:
    cur = el
    for n in nomi:
        cur = _figlio(cur, n) if cur is not None else None
    return (cur.text or "").strip() if cur is not None and cur.text else ""


def riepilogo_fattura(dati: bytes) -> Optional[dict]:
    try:
        root = ET.fromstring(dati)
    except Exception:
        return None
    if _loc(root.tag) != 'FatturaElettronica':
        return None
    h, b = _figlio(root, 'FatturaElettronicaHeader'), _figlio(root, 'FatturaElettronicaBody')
    if h is None:
        return None

    def anagrafica(sezione):
        a = _percorso(h, sezione, 'DatiAnagrafici', 'Anagrafica', 'Denominazione')
        if not a:
            a = (_percorso(h, sezione, 'DatiAnagrafici', 'Anagrafica', 'Nome') + " " +
                 _percorso(h, sezione, 'DatiAnagrafici', 'Anagrafica', 'Cognome')).strip()
        return a

    out = {
        "Cedente / prestatore": anagrafica('CedentePrestatore'),
        "P.IVA cedente": _percorso(h, 'CedentePrestatore', 'DatiAnagrafici', 'IdFiscaleIVA', 'IdCodice'),
        "Cessionario / committente": anagrafica('CessionarioCommittente'),
        "P.IVA cessionario": _percorso(h, 'CessionarioCommittente', 'DatiAnagrafici', 'IdFiscaleIVA', 'IdCodice'),
        "Progressivo invio": _percorso(h, 'DatiTrasmissione', 'ProgressivoInvio'),
        "Codice destinatario": _percorso(h, 'DatiTrasmissione', 'CodiceDestinatario'),
    }
    if b is not None:
        out.update({
            "Tipo documento": _percorso(b, 'DatiGenerali', 'DatiGeneraliDocumento', 'TipoDocumento'),
            "Numero": _percorso(b, 'DatiGenerali', 'DatiGeneraliDocumento', 'Numero'),
            "Data": _percorso(b, 'DatiGenerali', 'DatiGeneraliDocumento', 'Data'),
            "Importo totale": (_percorso(b, 'DatiGenerali', 'DatiGeneraliDocumento', 'ImportoTotaleDocumento') + " " +
                               _percorso(b, 'DatiGenerali', 'DatiGeneraliDocumento', 'Divisa')).strip(),
        })
    return {k: v for k, v in out.items() if v}


NS_DS = "http://www.w3.org/2000/09/xmldsig#"
_DS = "{%s}" % NS_DS
_XML_HASH = {"xmldsig#sha1": "sha1", "xmlenc#sha256": "sha256", "xmldsig-more#sha224": "sha224", "xmldsig-more#sha384": "sha384",
             "xmlenc#sha512": "sha512", "xmldsig-more#sha512": "sha512", "xmlenc#sha384": "sha384"}


def _alg_hash_xml(uri: str) -> Optional[str]:
    return next((v for k, v in _XML_HASH.items() if uri.endswith(k)), None)


def _parser_xml():
    return etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=True, remove_blank_text=False)


def _c14n(nodo, alg: str) -> bytes:
    return etree.tostring(nodo, method="c14n", exclusive="xml-exc-c14n" in alg, with_comments=alg.endswith("WithComments"))


def _togli_nodo(el):
    """Rimuove un elemento lasciando il testo che lo segue (etree.remove lo perderebbe)."""
    padre, coda = el.getparent(), el.tail
    if coda:
        prec = el.getprevious()
        if prec is not None:
            prec.tail = (prec.tail or "") + coda
        else:
            padre.text = (padre.text or "") + coda
    padre.remove(el)


def _mappa_id(radice) -> Tuple[dict, set]:
    ids, doppi = {}, set()
    for e in radice.iter():
        if not isinstance(e.tag, str):
            continue
        for a in ("Id", "ID", "id"):
            v = e.get(a)
            if v:
                if v in ids and ids[v] is not e:
                    doppi.add(v)
                ids[v] = e
    return ids, doppi


def _verifica_riferimento(rif, sig_indice: int, dati: bytes) -> Tuple[Optional[bool], str, bool]:
    """Ricalcola l'impronta di un ds:Reference su una copia fresca del documento. -> (esito, messaggio, copre l'intero documento)"""
    albero = etree.parse(io.BytesIO(dati), _parser_xml())
    radice = albero.getroot()
    firma = list(radice.iter())[sig_indice]
    uri = rif.get("URI")
    if uri is None or (uri and not uri.startswith("#")):
        return None, f"riferimento esterno non verificabile ({uri})", False
    if uri in ("", "#xpointer(/)"):
        nodo, copre = albero, True
    else:
        ident = re.sub(r"^#xpointer\(id\('(.*)'\)\)$", r"\1", uri).lstrip("#")
        ids, doppi = _mappa_id(radice)
        if ident in doppi:
            return False, f"Id «{ident}» duplicato nel documento: possibile manomissione", False
        if ident not in ids:
            return False, f"elemento «{ident}» firmato non trovato", False
        nodo, copre = ids[ident], ids[ident] is radice
    c14n_alg = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    trasf = rif.find(_DS + "Transforms")
    for t in (trasf if trasf is not None else []):
        if not isinstance(t.tag, str):
            continue
        alg = t.get("Algorithm", "")
        if alg.endswith("#enveloped-signature"):
            _togli_nodo(firma)
        elif "c14n" in alg:
            c14n_alg = alg
        elif alg.endswith("REC-xpath-19991116") or alg.endswith("xmldsig-filter2"):
            testo = " ".join((x.text or "") for x in t if isinstance(x.tag, str))
            if "Signature" not in testo or not ("not(" in testo or any(x.get("Filter") == "subtract" for x in t if isinstance(x.tag, str))):
                return None, f"trasformazione XPath non supportata ({testo.strip()[:60]})", False
            for s in list(radice.iter(_DS + "Signature")):
                _togli_nodo(s)
        else:
            return None, f"trasformazione non supportata ({alg})", False
    dm, dv = rif.find(_DS + "DigestMethod"), rif.find(_DS + "DigestValue")
    algo = _alg_hash_xml(dm.get("Algorithm", "")) if dm is not None else None
    if algo is None or dv is None:
        return None, "algoritmo di impronta non supportato", False
    calcolata = hashlib.new(algo, _c14n(nodo, c14n_alg)).digest()
    if calcolata != base64.b64decode("".join((dv.text or "").split())):
        return False, f"l'impronta del riferimento «{uri or 'documento'}» non corrisponde: documento alterato", copre
    return True, "", copre


def verifica_xmldsig(firma, radice, dati: bytes, cert) -> Tuple[Optional[bool], str, Optional[bool]]:
    """Verifica un ds:Signature: riferimenti + SignedInfo. -> (esito, messaggio, firma copre l'intero documento)"""
    if etree is None or not HAS_CRYPTO:
        return None, "librerie lxml/cryptography non disponibili", None
    try:
        si = firma.find(_DS + "SignedInfo")
        sv = firma.find(_DS + "SignatureValue")
        if si is None or sv is None:
            return False, "struttura ds:Signature incompleta", None
        indice = list(radice.iter()).index(firma)
        rifs = si.findall(_DS + "Reference")
        if not rifs:
            return False, "nessun riferimento firmato", None
        copre = False
        for r in rifs:
            esito, msg, c = _verifica_riferimento(r, indice, dati)
            if esito is not True:
                return esito, msg, None
            copre = copre or c
        c14n_alg = si.find(_DS + "CanonicalizationMethod").get("Algorithm", "")
        alg_uri = si.find(_DS + "SignatureMethod").get("Algorithm", "")
        canonico = _c14n(si, c14n_alg)
        valore = base64.b64decode("".join((sv.text or "").split()))
        chiave = serialization.load_der_public_key(cert['tbs_certificate']['subject_public_key_info'].dump())
        nome_h = next((n for n in ("sha3-256", "sha3-384", "sha3-512", "sha224", "sha256", "sha384", "sha512", "sha1") if n in alg_uri.lower()), None)
        if nome_h is None:
            return None, f"algoritmo di firma non supportato ({alg_uri})", copre
        h = _HASH_CLASSI[nome_h.replace("-", "_")]()
        if "MGF1" in alg_uri or "rsa-pss" in alg_uri.lower():
            chiave.verify(valore, canonico, padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size), h)
        elif "ecdsa" in alg_uri.lower():
            meta = len(valore) // 2
            der = encode_dss_signature(int.from_bytes(valore[:meta], "big"), int.from_bytes(valore[meta:], "big"))
            chiave.verify(der, canonico, ec.ECDSA(h))
        elif "rsa" in alg_uri.lower():
            chiave.verify(valore, canonico, padding.PKCS1v15(), h)
        else:
            return None, f"algoritmo di firma non supportato ({alg_uri})", copre
        return True, "riferimenti e firma crittografica verificati: documento integro", copre
    except InvalidSignature:
        return False, "firma crittografica non valida: documento alterato o firma corrotta", None
    except Exception as e:
        return None, f"verifica non eseguibile ({type(e).__name__}: {e})", None


def _certificato_xades(firma, certs) -> Tuple[Optional[x509.Certificate], Optional[Controllo]]:
    """Sceglie il certificato del firmatario: quello indicato da xades:SigningCertificate, se presente."""
    nome = "Legame firma-certificato"
    non_ca = [c for c in certs if not getattr(c, 'ca', False)]
    scelto = non_ca[0] if non_ca else (certs[0] if certs else None)
    digest_attesi = []
    for e in firma.iter():
        if isinstance(e.tag, str) and _loc(e.tag) in ("SigningCertificate", "SigningCertificateV2"):
            for cd in e.iter():
                if isinstance(cd.tag, str) and _loc(cd.tag) == "CertDigest":
                    dm, dv = cd.find(_DS + "DigestMethod"), cd.find(_DS + "DigestValue")
                    if dm is not None and dv is not None:
                        digest_attesi.append((_alg_hash_xml(dm.get("Algorithm", "")), "".join((dv.text or "").split())))
    if not digest_attesi:
        return scelto, Controllo(nome, "none", "elemento SigningCertificate assente")
    for algo, valore in digest_attesi:
        if not algo:
            continue
        for c in certs:
            if base64.b64encode(hashlib.new(algo, c.dump()).digest()).decode() == valore:
                return c, Controllo(nome, "ok", "SigningCertificate corrisponde al certificato usato")
    return scelto, Controllo(nome, "error", "SigningCertificate indica un certificato diverso da quello incluso")


async def analizza_xml(ris: RisultatoDoc, valida: bool = True):
    try:
        with open(ris.percorso, 'rb') as f:
            dati = f.read()
        if etree is None:
            ris.errore = "Libreria lxml non disponibile"
            return
        radice = etree.fromstring(dati, _parser_xml())
    except Exception:
        ris.errore = "XML malformato o non leggibile"
        return
    if ris.dimensione < 30_000_000:
        ris.fattura = riepilogo_fattura(dati)
    for firma in list(radice.iter(_DS + "Signature")):
        fi = FirmaInfo(formato="XAdES")
        certs = []
        for e in firma.iter(_DS + "X509Certificate"):
            if e.text:
                try:
                    certs.append(x509.Certificate.load(base64.b64decode("".join(e.text.split()))))
                except Exception:
                    pass
        for e in firma.iter():
            if isinstance(e.tag, str) and _loc(e.tag) == 'SigningTime' and e.text:
                fi.data_firma = parse_iso(e.text)
                fi.fonte_data = "Elemento SigningTime (XAdES)"
                break
        if not certs:
            fi.stato, fi.esito = "error", "Firma XML senza certificato del firmatario"
            fi.controlli.append(Controllo("Certificato", "error", "non presente nella firma"))
            ris.firme.append(fi)
            continue
        cert, legame = _certificato_xades(firma, certs)
        popola_da_cert(fi, cert)
        sm = firma.find(_DS + "SignedInfo/" + _DS + "SignatureMethod")
        rm = firma.find(_DS + "SignedInfo/" + _DS + "Reference/" + _DS + "DigestMethod")
        fi.algo_firma = (sm.get("Algorithm", "").rsplit("#", 1)[-1] if sm is not None else "")
        fi.algo_hash = (_alg_hash_xml(rm.get("Algorithm", "")) or "") if rm is not None else ""
        if not valida:
            fi.esito = "Verifica non eseguita (solo estrazione)"
            ris.firme.append(fi)
            continue
        fi.integrita, fi.integrita_msg, copre = verifica_xmldsig(firma, radice, dati, cert)
        fi.controlli.append(controllo_integrita(fi))
        if fi.integrita and copre is False:
            fi.controlli.append(Controllo("Copertura", "warn", "la firma copre solo una parte del documento"))
        fi.controlli.append(legame)
        msg_marca = ""
        for e in firma.iter():
            if isinstance(e.tag, str) and _loc(e.tag) == "EncapsulatedTimeStamp" and e.text:
                try:
                    token = cms.ContentInfo.load(base64.b64decode("".join(e.text.split())))
                    cm = next((x for x in e.getparent() if isinstance(x.tag, str) and _loc(x.tag) == "CanonicalizationMethod"), None)
                    alg = cm.get("Algorithm", "") if cm is not None else ""
                    sv = firma.find(_DS + "SignatureValue")
                    fi.marca_valida, istante, fi.marca_tsa, msg_marca = await verifica_marca(token, _c14n(sv, alg))
                    fi.marca_temporale = istante
                except Exception as ex:
                    fi.marca_valida, msg_marca = None, f"marca non leggibile ({type(ex).__name__})"
                break
        fi.controlli.append(controllo_marca(fi, msg_marca))
        fi.controlli += await valida_certificato(cert, certs, fi.data_firma, fi.marca_temporale if fi.marca_valida else None)
        fi.controlli.append(controllo_algoritmi(fi, cert))
        fi.controlli.append(controllo_tipo_certificato(cert))
        t = controllo_tempi(fi)
        if t is not None:
            fi.controlli.append(t)
        combina_esito(fi)
        ris.firme.append(fi)


# ============================================================ ORCHESTRATORE
def _tipo_reale(path: str) -> str:
    """Il tipo si riconosce dal contenuto; l'estensione conta solo se il contenuto non dice nulla."""
    with open(path, 'rb') as f:
        testa = f.read(2048)
    if _sembra_der(testa):                  # prima la busta: dentro i primi byte puo' esserci il PDF firmato
        return '.p7m'
    if b'%PDF-' in testa[:1024]:
        return '.pdf'
    t = testa.lstrip(b'\xef\xbb\xbf \r\n\t')
    if t[:1] == b'<':
        return '.xml'
    if t[:2] in (b'MI', b'MB', b'MD') or t.startswith(b'-----BEGIN'):
        return '.p7m'
    return ''


async def analizza_file(path: str, valida: bool = True) -> RisultatoDoc:
    t0 = time.time()
    nome = os.path.basename(path)
    ext = tipo_documento(nome)
    ris = RisultatoDoc(percorso=path, nome=nome, verificato=valida)
    try:
        ris.dimensione = os.path.getsize(path)
        reale = _tipo_reale(path)
        if reale and reale != ext and not (reale == '.p7m' and ext == '.p7s'):
            if ext in ESTENSIONI_VERIFICA:
                ris.note.append(f"L'estensione {ext} non corrisponde al contenuto: analizzato come {reale}")
            ext = reale
        ris.formato = {'.p7m': 'CAdES', '.p7s': 'CAdES', '.pdf': 'PAdES', '.xml': 'XAdES'}.get(ext, '?')
        ris.sha256 = await asyncio.to_thread(sha256_file, path)
        if ext in ('.p7m', '.p7s'):
            await analizza_p7m(ris, valida)
        elif ext == '.pdf':
            await analizza_pdf(ris, valida)
        elif ext == '.xml':
            await analizza_xml(ris, valida)
        else:
            ris.errore = "Formato non supportato"
    except PermissionError:
        ris.errore = "Accesso al file negato"
    except Exception as e:
        ris.errore = f"Errore imprevisto: {type(e).__name__}: {e}"
    ris.durata = time.time() - t0
    ris.finalizza()
    return ris


# ============================================================ REPORT / EXPORT
def report_testuale(r: RisultatoDoc) -> str:
    L = [f"File: {r.nome}", f"Percorso: {r.percorso}", f"Formato: {r.formato}",
         f"Dimensione: {fmt_size(r.dimensione)}", f"SHA-256: {r.sha256}",
         f"Esito complessivo: {etichetta_doc(r)} - {r.esito}", f"Firme rilevate: {len(r.firme)}"]
    if r.nome_contenuto and r.formato == 'CAdES':
        L.append(f"Documento contenuto: {r.nome_contenuto} ({r.tipo_contenuto})")
    if r.estr_esito:
        L.append(f"Estrazione: {ETICHETTA_ESTRAZIONE[r.estr_esito]} - {r.estr_dettaglio}")
    L += [f"Nota: {n}" for n in r.note]
    for i, f in enumerate(r.firme, 1):
        L += ["", f"--- {f.tipo} {i} ---", f"Firmatario: {f.firmatario}"]
        if f.identificativo:
            L.append(f"Identificativo: {f.identificativo}")
        if f.organizzazione:
            L.append(f"Organizzazione: {f.organizzazione}")
        L.append(f"Data e ora firma: {fmt_dt(f.data_firma)}" + (f"  [{f.fonte_data}]" if f.fonte_data else ""))
        if f.data_pdf_m:
            L.append(f"Data /M del PDF: {fmt_dt(f.data_pdf_m)}")
        if f.marca_temporale:
            L.append(f"Marca temporale: {fmt_dt(f.marca_temporale)}")
        L += [f"Emittente: {f.emittente}", f"Certificato valido dal {fmt_data(f.valido_dal)} al {fmt_data(f.valido_al)}",
              f"Esito: {etichetta_firma(f)} - {f.esito}", "Controlli:"]
        simboli = {"ok": "[OK]", "warn": "[!!]", "error": "[KO]", "none": "[--]"}
        L += [f"  {simboli[c.stato]} {c.nome}: {c.dettaglio}" for c in f.controlli]
        L += [f"Nota: {n}" for n in f.note]
    L += ["", f"Verifica eseguita il {fmt_dt(datetime.datetime.now().astimezone())} con {APP_NAME} {APP_VERSION}"]
    return "\n".join(L)


def esporta_csv(risultati: List[RisultatoDoc], path: str):
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f, delimiter=';')
        w.writerow(["File", "Percorso", "Formato", "Dimensione", "SHA-256", "Stato documento", "Esito documento", "Estrazione",
                    "Documento estratto", "N. firme", "Tipo", "Firmatario", "Identificativo", "Organizzazione", "Data firma",
                    "Ora firma", "Fonte data", "Marca temporale", "Marca valida", "Cert. valido dal", "Cert. valido al",
                    "Emittente", "Integrita'", "Esito firma", "Controlli"])
        for r in risultati:
            base = [r.nome, r.percorso, r.formato, r.dimensione, r.sha256, etichetta_doc(r), r.esito,
                    ETICHETTA_ESTRAZIONE[r.estr_esito] if r.estr_esito else "", r.estr_dettaglio, len(r.firme)]
            if not r.firme:
                w.writerow(base + [""] * 15)
            for fi in r.firme:
                w.writerow(base + [fi.tipo, fi.firmatario, fi.identificativo, fi.organizzazione, fmt_data(fi.data_firma),
                                   fmt_ora(fi.data_firma) if fi.data_firma else "", fi.fonte_data,
                                   fmt_dt(fi.marca_temporale) if fi.marca_temporale else "",
                                   {True: "si", False: "no", None: ""}[fi.marca_valida],
                                   fmt_data(fi.valido_dal), fmt_data(fi.valido_al), fi.emittente,
                                   {True: "verificata", False: "NON valida", None: "non verificabile"}[fi.integrita],
                                   f"{etichetta_firma(fi)} - {fi.esito}",
                                   " | ".join(f"{c.nome}: {c.dettaglio}" for c in fi.controlli)])


def esporta_html(risultati: List[RisultatoDoc], path: str):
    colori = {"ok": "#22A06B", "warn": "#E8A317", "error": "#E5484D", "none": "#8A94A6"}
    e = html.escape
    tot = {k: sum(1 for r in risultati if r.stato == k) for k in colori}
    righe = []
    for r in risultati:
        estr = f"<br><small>Estrazione: {e(ETICHETTA_ESTRAZIONE[r.estr_esito])} · {e(r.estr_dettaglio)}</small>" if r.estr_esito else ""
        righe.append(f"<tr class='doc'><td><span class='b' style='background:{colori[r.stato]}'>{e(etichetta_doc(r))}</span></td>"
                     f"<td><b>{e(r.nome)}</b><br><small>{e(r.formato)} · {e(fmt_size(r.dimensione))}<br>SHA-256 {e(r.sha256[:32])}…</small>{estr}</td>"
                     f"<td colspan='3'>{e(r.esito)}</td></tr>")
        for fi in r.firme:
            controlli = "".join(f"<li style='color:{colori[c.stato]}'><span style='color:#344054'>{e(c.nome)}: {e(c.dettaglio)}</span></li>" for c in fi.controlli)
            righe.append(f"<tr><td></td><td>↳ {e(fi.tipo)}: <b>{e(fi.firmatario)}</b><br><small>{e(fi.identificativo)}</small></td>"
                         f"<td>{e(fmt_dt(fi.data_firma))}<br><small>{e(fi.fonte_data)}</small></td>"
                         f"<td>{e(fi.emittente)}<br><small>valido {e(fmt_data(fi.valido_dal))} → {e(fmt_data(fi.valido_al))}</small></td>"
                         f"<td><span class='b' style='background:{colori[fi.stato]}'>{e(etichetta_firma(fi))}</span> {e(fi.esito)}<ul>{controlli}</ul></td></tr>")
    ora = fmt_dt(datetime.datetime.now().astimezone())
    doc = f"""<!doctype html><html lang="it"><head><meta charset="utf-8"><title>Report verifica firme</title>
<style>body{{font:14px Segoe UI,Arial,sans-serif;margin:32px;color:#101828;background:#f2f4f8}}
h1{{color:#4C57CC;margin:0 0 4px}}table{{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden}}
td,th{{padding:8px 10px;border-right:1px solid #e3e7ee;vertical-align:top;text-align:left}}th{{background:#13141B;color:#fff}}
tr.doc td{{background:#f6f8fb}}.b{{color:#fff;border-radius:8px;padding:2px 8px;font-size:12px;font-weight:600}}
small{{color:#667085}}ul{{margin:6px 0 0;padding-left:18px;font-size:12px}}.k{{display:inline-block;margin-right:18px;font-weight:600}}</style></head><body>
<h1>Report di verifica firme</h1><p>Generato il {e(ora)} con {APP_NAME} {APP_VERSION}</p>
<p><span class='k'>Totale: {len(risultati)}</span><span class='k' style='color:#22A06B'>Verificati: {tot['ok']}</span>
<span class='k' style='color:#E8A317'>Attenzione: {tot['warn'] + tot['none']}</span><span class='k' style='color:#E5484D'>Non validi: {tot['error']}</span></p>
<table><tr><th>Stato</th><th>Documento / firmatario</th><th>Data e ora firma</th><th>Emittente</th><th>Esito e controlli</th></tr>
{''.join(righe)}</table></body></html>"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(doc)


def descrivi_certificato(der: bytes) -> str:
    c = x509.Certificate.load(der)
    L = ["SOGGETTO", "  " + c.subject.human_friendly.replace("; ", "\n  "), "",
         "EMITTENTE", "  " + c.issuer.human_friendly.replace("; ", "\n  "), "",
         f"Numero di serie : {format(c.serial_number, 'X')}"]
    try:
        v = c['tbs_certificate']['validity']
        L.append(f"Valido dal      : {fmt_dt(v['not_before'].native)}")
        L.append(f"Valido fino al  : {fmt_dt(v['not_after'].native)}")
    except Exception:
        pass
    try:
        L.append(f"Chiave pubblica : {c.public_key.algorithm.upper()} {c.public_key.bit_size} bit")
        L.append(f"Algoritmo firma : {c.signature_algo} / {c.hash_algo}")
    except Exception:
        pass
    try:
        L.append(f"CA              : {'si' if c.ca else 'no'}")
    except Exception:
        pass
    for etichetta, attr in (("Uso chiave      ", 'key_usage_value'), ("Uso esteso      ", 'extended_key_usage_value')):
        try:
            val = getattr(c, attr)
            if val is not None:
                L.append(f"{etichetta}: {', '.join(sorted(str(x) for x in val.native))}")
        except Exception:
            pass
    try:
        pol = [str(p['policy_identifier']) for p in c.certificate_policies_value.native]
        if pol:
            L.append("Policy          : " + ", ".join(pol))
    except Exception:
        pass
    try:
        if c.ocsp_urls:
            L.append("OCSP            : " + ", ".join(c.ocsp_urls))
    except Exception:
        pass
    try:
        for dp in (c.crl_distribution_points or []):
            L.append(f"CRL             : {dp.native.get('distribution_point')}")
    except Exception:
        pass
    sha1, sha256 = hashlib.sha1(der).hexdigest().upper(), hashlib.sha256(der).hexdigest().upper()
    fp = lambda h: ":".join(h[i:i + 2] for i in range(0, len(h), 2))
    L += ["", "IMPRONTE", f"  SHA-1   : {fp(sha1)}", f"  SHA-256 : {fp(sha256)}"]
    return "\n".join(L)


# ============================================================ UI: TEMA
C_SCURO = {"sfondo": "#13141B", "superficie": "#1A1B24", "rilievo": "#22232E", "hover": "#2A2C39", "bordo": "#2E303D",
           "bordo_tenue": "#24252F", "testo": "#E8E9F0", "attenuato": "#A0A3B8", "tenue": "#6F7287", "accento": "#8E9DFF",
           "accento_chiaro": "#A9B5FF", "accento_scuro": "#4C57CC", "accento_medio": "#6B79EE", "su_accento": "#0D0E15",
           "selezione": "#2D3253", "ok": "#5CD3A0", "warn": "#F4C46A", "error": "#F2738D", "none": "#8E92A8", "info": "#7CC4F5",
           "riga_hover": "#232533", "carta_hover": "#1D1E29", "carta_bordo_hover": "#3B3E58", "sugg_sfondo": "#1E2033",
           "sugg_bordo": "#343A66", "pericolo_bordo": "#4E2E3A", "pericolo_hover": "#2E1F27", "barra": "#0E0F15",
           "zona_a": "#1E2034", "zona_b": "#181924", "cerchio": "#252842", "dettaglio": "#17181F", "scroll": "#3A3C50", "scroll_hover": "#545873"}
C_CHIARO = {"sfondo": "#F3F4F9", "superficie": "#FFFFFF", "rilievo": "#EEF0F6", "hover": "#E3E6F0", "bordo": "#D5D8E3",
            "bordo_tenue": "#E2E4EC", "testo": "#1B1D29", "attenuato": "#555970", "tenue": "#7B7F95", "accento": "#4C57CC",
            "accento_chiaro": "#3F49B5", "accento_scuro": "#7C88EE", "accento_medio": "#6B79EE", "su_accento": "#FFFFFF",
            "selezione": "#DDE1FA", "ok": "#14855A", "warn": "#A66A00", "error": "#C9304F", "none": "#6E7288", "info": "#1C74B8",
            "riga_hover": "#F0F2F9", "carta_hover": "#FAFAFE", "carta_bordo_hover": "#BFC4DC", "sugg_sfondo": "#EEF0FD",
            "sugg_bordo": "#C7CDF2", "pericolo_bordo": "#EDC3CD", "pericolo_hover": "#FBEDF0", "barra": "#E4E6EF",
            "zona_a": "#F4F5FF", "zona_b": "#FFFFFF", "cerchio": "#E4E7FB", "dettaglio": "#F7F8FC", "scroll": "#C4C7D6", "scroll_hover": "#A0A4B8"}
C = dict(C_SCURO)

ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#A9B5FF"/><stop offset="1" stop-color="#6B79EE"/></linearGradient></defs>
<rect x="6" y="6" width="116" height="116" rx="28" fill="#1A1B24"/>
<path d="M36 18h38l24 24v30M98 72M60 106H36a8 8 0 0 1-8-8V26a8 8 0 0 1 8-8" fill="none" stroke="url(#g)" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
<path d="M74 18v24h24" fill="none" stroke="url(#g)" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
<path d="M40 76c7-17 12-22 15-17 3 6-6 21-2 22 4 1 8-13 12-11 3 2 0 8 4 8 2 0 4-2 6-3" fill="none" stroke="#E8E9F0" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="90" cy="92" r="23" fill="#13141B" stroke="#5CD3A0" stroke-width="7"/>
<path d="M80 92l7.5 7.5L101 85" fill="none" stroke="#5CD3A0" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"""

_TRACCIATI = {
    "cartella": "M3 7.5A2.5 2.5 0 0 1 5.5 5H9l2 2h7.5A2.5 2.5 0 0 1 21 9.5v8a2.5 2.5 0 0 1-2.5 2.5h-13A2.5 2.5 0 0 1 3 17.5z",
    "cerca": "M10.5 4a6.5 6.5 0 1 0 0 13a6.5 6.5 0 1 0 0-13z M15.5 15.5L20 20",
    "scarica": "M12 4v11 M7.5 10.5L12 15l4.5-4.5 M4.5 19.5h15",
    "apri": "M13.5 4.5h6v6 M19.5 4.5l-8.5 8.5 M18 14v5.5H4.5V6H10",
    "scudo": "M12 3l7.5 3v5.5c0 4.5-3.2 8-7.5 9.5-4.3-1.5-7.5-5-7.5-9.5V6z M8.8 12l2.2 2.2 4.3-4.4",
    "cestino": "M4 7h16 M9.5 7V4.5h5V7 M6 7l1 13h10l1-13 M10 11v5.5 M14 11v5.5",
    "documento": "M6 3h8.5L19 7.5V21H6z M14 3v5h5 M9 13h7 M9 16.5h7",
    "casa": "M3.5 11L12 4l8.5 7 M6 9.5V20h12V9.5 M10 20v-5h4v5",
    "aggiorna": "M19.5 12a7.5 7.5 0 1 1-2.2-5.3 M19.5 4.5v4.5H15",
    "certificato": "M4 4.5h16v11H4z M8 8.5h8 M8 11.5h5 M15 15.5l-1.5 5 2.5-1.5 2.5 1.5-1.5-5",
    "tabella": "M4 5h16v14H4z M4 10h16 M4 14.5h16 M10 5v14",
    "carica": "M12 16V4.5 M7.5 9L12 4.5 16.5 9 M4.5 15.5V19.5h15v-4",
    "copia": "M8.5 8.5h11v11h-11z M5 15.5H4.5V4.5h11V5",
    "chiudi": "M6.5 6.5l11 11 M17.5 6.5l-11 11",
    "pacco": "M12 3l8 4.5v9L12 21l-8-4.5v-9z M4 7.5l8 4.5 8-4.5 M12 12v9",
    "ingranaggio": "M12 8.8a3.2 3.2 0 1 0 0 6.4a3.2 3.2 0 1 0 0-6.4z M12 3v2.5 M12 18.5V21 M3 12h2.5 M18.5 12H21 M5.6 5.6l1.8 1.8 M16.6 16.6l1.8 1.8 M18.4 5.6l-1.8 1.8 M7.4 16.6l-1.8 1.8",
    "luna": "M20 14.5A8.5 8.5 0 1 1 9.5 4a7 7 0 0 0 10.5 10.5z",
    "fattura": "M6 3h12v18l-3-2-3 2-3-2-3 2z M9 8h6 M9 12h6",
    "espandi": "M8 9.5l4-4 4 4 M8 14.5l4 4 4-4",
}
_cache_icone = {}


class _Bus(QObject):
    tema = pyqtSignal()
    tsl = pyqtSignal()


BUS = _Bus()


def icona(nome, colore=None, dimensione=18):
    colore = colore or C["testo"]
    chiave = (nome, colore, dimensione)
    if chiave not in _cache_icone:
        lato = dimensione * 2
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="{lato}" height="{lato}">'
               f'<path d="{_TRACCIATI.get(nome, _TRACCIATI["documento"])}" fill="none" stroke="{colore}" '
               f'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>')
        pix = QPixmap()
        pix.loadFromData(svg.encode('utf-8'))
        _cache_icone[chiave] = QIcon(pix)
    return _cache_icone[chiave]


def icona_app() -> QIcon:
    ic = QIcon()
    for lato in (16, 24, 32, 48, 64, 128, 256):
        pix = QPixmap()
        svg = ICON_SVG.replace('viewBox="0 0 128 128"', f'viewBox="0 0 128 128" width="{lato}" height="{lato}"')
        pix.loadFromData(svg.encode('utf-8'))
        ic.addPixmap(pix)
    return ic


def pallino(colore, lato=10) -> QIcon:
    pix = QPixmap(lato * 2, lato * 2)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(colore))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(QRectF(2, 2, lato * 2 - 4, lato * 2 - 4))
    p.end()
    return QIcon(pix)


def pulsante(testo, nome_icona=None, ruolo=None, suggerimento=None):
    b = QPushButton(testo)
    if nome_icona:
        def imposta():
            if sip.isdeleted(b):
                return
            r = ruolo or ""
            colore = C["su_accento"] if "primario" in r else C["error"] if "pericolo" in r else C["accento_chiaro"]
            b.setIcon(icona(nome_icona, colore))
        imposta()
        b.setIconSize(QSize(16, 16))
        BUS.tema.connect(imposta)
    if ruolo:
        b.setProperty("ruolo", ruolo)
    if suggerimento:
        b.setToolTip(suggerimento)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


def etichetta(testo, nome=None, a_capo=False):
    l = QLabel(testo)
    if nome:
        l.setObjectName(nome)
    l.setWordWrap(a_capo)
    return l


def foglio_stile() -> str:
    FONT = "'Segoe UI Variable Text', 'Segoe UI', 'Inter', sans-serif"
    return f"""
* {{ outline: 0; }}
QWidget {{ color: {C['testo']}; font-family: {FONT}; font-size: 13px; }}
QMainWindow, QDialog, QWidget#sfondo, QStackedWidget, QScrollArea {{ background-color: {C['sfondo']}; border: none; }}
QLabel {{ background: transparent; }}
QLabel#titolo {{ font-size: 26px; font-weight: 700; }}
QLabel#titoloMedio {{ font-size: 17px; font-weight: 700; }}
QLabel#sottotitolo {{ color: {C['attenuato']}; font-size: 14px; }}
QLabel#etichetta {{ color: {C['tenue']}; font-size: 11px; font-weight: 700; letter-spacing: 1px; }}
QLabel#attenuato {{ color: {C['attenuato']}; }}
QLabel#marchio {{ font-size: 15px; font-weight: 700; }}
QLabel#versione {{ color: {C['tenue']}; font-size: 12px; }}
QWidget#barraTitolo {{ background-color: {C['superficie']}; border-bottom: 1px solid {C['bordo_tenue']}; }}
QFrame#carta {{ background-color: {C['superficie']}; border: 1px solid {C['bordo_tenue']}; border-radius: 14px; }}
QFrame#carta:hover {{ border-color: {C['carta_bordo_hover']}; background-color: {C['carta_hover']}; }}
QFrame#pannello {{ background-color: {C['superficie']}; border: 1px solid {C['bordo_tenue']}; border-radius: 12px; }}
QFrame#suggerimento {{ background-color: {C['sugg_sfondo']}; border: 1px solid {C['sugg_bordo']}; border-radius: 10px; }}
QFrame#dettaglio {{ background-color: {C['dettaglio']}; border: none; border-left: 2px solid {C['accento']}; }}
QPushButton {{ background-color: {C['rilievo']}; color: {C['testo']}; border: 1px solid {C['bordo']}; border-radius: 8px; padding: 7px 14px; font-weight: 600; }}
QPushButton:hover {{ background-color: {C['hover']}; }}
QPushButton:disabled {{ color: {C['tenue']}; background-color: {C['superficie']}; border-color: {C['bordo_tenue']}; }}
QPushButton[ruolo~="primario"] {{ background-color: {C['accento']}; color: {C['su_accento']}; border: 1px solid {C['accento']}; }}
QPushButton[ruolo~="primario"]:hover {{ background-color: {C['accento_chiaro']}; border-color: {C['accento_chiaro']}; }}
QPushButton[ruolo~="pericolo"] {{ background-color: transparent; color: {C['error']}; border-color: {C['pericolo_bordo']}; }}
QPushButton[ruolo~="pericolo"]:hover {{ background-color: {C['pericolo_hover']}; }}
QPushButton[ruolo~="fantasma"] {{ background-color: transparent; border-color: transparent; color: {C['attenuato']}; }}
QPushButton[ruolo~="fantasma"]:hover {{ background-color: {C['rilievo']}; color: {C['testo']}; }}
QPushButton[ruolo~="piccolo"] {{ padding: 3px 10px; font-size: 12px; border-radius: 6px; }}
QPushButton[ruolo~="filtro"] {{ background-color: transparent; border: 1px solid transparent; color: {C['attenuato']}; padding: 5px 12px; border-radius: 10px; }}
QPushButton[ruolo~="filtro"]:hover {{ background-color: {C['rilievo']}; color: {C['testo']}; }}
QPushButton[ruolo~="filtro"]:checked {{ background-color: {C['selezione']}; color: {C['testo']}; border-color: {C['accento_scuro']}; }}
QPushButton::menu-indicator {{ width: 0; }}
QAbstractScrollArea::corner {{ background: transparent; border: none; }}
QLineEdit, QComboBox {{ background-color: {C['rilievo']}; border: 1px solid {C['bordo']}; border-radius: 8px; padding: 6px 12px; selection-background-color: {C['accento']}; selection-color: {C['su_accento']}; }}
QLineEdit:focus, QComboBox:focus {{ border-color: {C['accento']}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{ background-color: {C['rilievo']}; border: 1px solid {C['bordo']}; selection-background-color: {C['selezione']}; selection-color: {C['testo']}; }}
QPlainTextEdit, QTextBrowser {{ background-color: {C['superficie']}; border: 1px solid {C['bordo_tenue']}; border-radius: 10px; padding: 6px; }}
QTreeWidget {{ background-color: {C['superficie']}; border: 1px solid {C['bordo_tenue']}; border-radius: 12px; }}
QTreeWidget::item {{ padding: 0 8px; border: none; }}
QTreeWidget::item:hover {{ background-color: {C['riga_hover']}; }}
QTreeWidget::item:selected {{ background-color: {C['selezione']}; color: {C['testo']}; }}
QHeaderView {{ background-color: transparent; }}
QHeaderView::section {{ background-color: {C['superficie']}; color: {C['tenue']}; border: none; border-right: 1px solid {C['bordo']}; border-bottom: 1px solid {C['bordo']}; padding: 8px 10px; font-weight: 700; font-size: 12px; }}
QHeaderView::section:last {{ border-right: none; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 15px; height: 15px; border-radius: 4px; border: 1px solid {C['bordo']}; background-color: {C['rilievo']}; }}
QCheckBox::indicator:checked {{ background-color: {C['accento']}; border-color: {C['accento']}; }}
QTabWidget::pane {{ border: none; top: 0px; }}
QTabBar {{ background: transparent; }}
QTabBar::tab {{ background: transparent; color: {C['attenuato']}; padding: 10px 18px; margin: 0 2px 0 0; border: none; border-bottom: 2px solid transparent; font-weight: 600; }}
QTabBar::tab:hover {{ color: {C['testo']}; background-color: {C['rilievo']}; border-top-left-radius: 8px; border-top-right-radius: 8px; }}
QTabBar::tab:selected {{ color: {C['testo']}; border-bottom: 2px solid {C['accento']}; }}
QScrollBar:vertical {{ background: transparent; width: 11px; margin: 3px; }}
QScrollBar::handle:vertical {{ background-color: {C['scroll']}; border-radius: 4px; min-height: 32px; }}
QScrollBar::handle:vertical:hover {{ background-color: {C['scroll_hover']}; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 3px; }}
QScrollBar::handle:horizontal {{ background-color: {C['scroll']}; border-radius: 4px; min-width: 32px; }}
QScrollBar::handle:horizontal:hover {{ background-color: {C['scroll_hover']}; }}
QScrollBar::add-line, QScrollBar::sub-line, QScrollBar::add-page, QScrollBar::sub-page {{ width: 0; height: 0; background: none; }}
QMenu {{ background-color: {C['rilievo']}; border: 1px solid {C['bordo']}; border-radius: 10px; padding: 6px; }}
QMenu::item {{ padding: 7px 24px 7px 12px; border-radius: 6px; }}
QMenu::item:selected {{ background-color: {C['selezione']}; }}
QMenu::separator {{ height: 1px; background-color: {C['bordo']}; margin: 5px 8px; }}
QProgressBar {{ background-color: {C['barra']}; border: 1px solid {C['bordo']}; border-radius: 8px; text-align: center; color: {C['testo']}; font-weight: 700; min-height: 18px; }}
QProgressBar::chunk {{ border-radius: 7px; background-color: {C['accento_medio']}; }}
QStatusBar {{ background-color: {C['superficie']}; color: {C['attenuato']}; border-top: 1px solid {C['bordo_tenue']}; }}
QStatusBar::item {{ border: none; }}
QToolTip {{ background-color: {C['rilievo']}; color: {C['testo']}; border: 1px solid {C['bordo']}; padding: 4px; }}
"""


def applica_tema():
    tema = IMP["tema"]
    if tema not in ("Light", "Dark"):
        try:
            tema = "Light" if QGuiApplication.styleHints().colorScheme() == Qt.ColorScheme.Light else "Dark"
        except Exception:
            tema = "Dark"
    C.clear()
    C.update(C_CHIARO if tema == "Light" else C_SCURO)
    _cache_icone.clear()
    QApplication.instance().setStyleSheet(foglio_stile())
    BUS.tema.emit()


def log_errore(testo):
    try:
        with open(os.path.join(cartella_config(), "errori.log"), "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now()}] {testo}\n")
    except Exception:
        pass


def avviso(parent, titolo, testo, tipo="info"):
    {"info": QMessageBox.information, "warn": QMessageBox.warning, "error": QMessageBox.critical}[tipo](parent, titolo, testo)


def conferma(parent, titolo, testo) -> bool:
    return QMessageBox.question(parent, titolo, testo) == QMessageBox.StandardButton.Yes


# ============================================================ UI: DIALOGHI
class DialogoCertificato(QDialog):
    def __init__(self, parent, fi: FirmaInfo):
        super().__init__(parent)
        self.fi = fi
        self.setWindowTitle(f"Certificato · {fi.firmatario}")
        self.resize(720, 620)
        lay = QVBoxLayout(self)
        lay.addWidget(etichetta("Dettagli del certificato", "titoloMedio"))
        try:
            self.testo = descrivi_certificato(fi.cert_der)
        except Exception as e:
            self.testo = f"Impossibile decodificare il certificato: {e}"
        box = QPlainTextEdit(self.testo)
        box.setReadOnly(True)
        box.setStyleSheet("font-family: Consolas, 'Courier New'; font-size: 12px;")
        lay.addWidget(box, 1)
        riga = QHBoxLayout()
        for testo, ic, fn in (("Copia", "copia", self.copia), ("Esporta .cer / .pem…", "scarica", self.esporta), ("Apri con Windows", "apri", self.apri)):
            b = pulsante(testo, ic)
            b.clicked.connect(fn)
            riga.addWidget(b)
        riga.addStretch()
        chiudi = pulsante("Chiudi", None, "primario")
        chiudi.clicked.connect(self.accept)
        riga.addWidget(chiudi)
        lay.addLayout(riga)

    def _base(self):
        return re.sub(r'[^a-zA-Z0-9_\-]', '_', self.fi.firmatario)

    def copia(self):
        QApplication.clipboard().setText(self.testo)

    def esporta(self):
        p, _ = QFileDialog.getSaveFileName(self, "Esporta certificato", f"Certificato_{self._base()}.cer",
                                           "Certificato X.509 DER (*.cer);;Certificato PEM (*.pem)")
        if p:
            try:
                with open(p, 'wb') as f:
                    f.write(pem.armor('CERTIFICATE', self.fi.cert_der) if p.lower().endswith('.pem') else self.fi.cert_der)
            except OSError as e:
                avviso(self, "Errore", f"Impossibile salvare: {e}", "error")

    def apri(self):
        p = os.path.join(tempfile.gettempdir(), f"cert_{self._base()}.cer")
        try:
            with open(p, 'wb') as f:
                f.write(self.fi.cert_der)
            apri_con_sistema(p)
        except OSError as e:
            avviso(self, "Errore", f"Impossibile aprire: {e}", "error")


class DialogoFattura(QDialog):
    def __init__(self, parent, nome, dati: dict):
        super().__init__(parent)
        self.setWindowTitle("Riepilogo fattura elettronica")
        self.resize(560, 460)
        lay = QVBoxLayout(self)
        lay.addWidget(etichetta("Fattura elettronica (FatturaPA)", "titoloMedio"))
        lay.addWidget(etichetta(nome, "attenuato", True))
        righe = "".join(f"<tr><td style='color:{C['attenuato']};padding:4px 14px 4px 0'>{html.escape(k)}</td>"
                        f"<td style='padding:4px 0'><b>{html.escape(v)}</b></td></tr>" for k, v in dati.items())
        t = QTextBrowser()
        t.setHtml(f"<table>{righe}</table>")
        lay.addWidget(t, 1)
        b = pulsante("Chiudi", None, "primario")
        b.clicked.connect(self.accept)
        lay.addWidget(b, 0, Qt.AlignmentFlag.AlignRight)


class DialogoAzione(QDialog):
    def __init__(self, parent, n, ci_sono_cartelle):
        super().__init__(parent)
        self.setWindowTitle("Che cosa vuoi fare?")
        self.setFixedWidth(500)
        self.azione = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 22, 24, 20)
        lay.setSpacing(12)
        testo = "Cartelle e file rilasciati" if ci_sono_cartelle else f"{n} document{'o' if n == 1 else 'i'}"
        lay.addWidget(etichetta(testo, "titoloMedio"))
        lay.addWidget(etichetta("Scegli l'operazione. In entrambi i casi vedrai la tabella con firmatari ed esiti.", "attenuato", True))
        self.sotto = QCheckBox("Includi le sottocartelle")
        self.sotto.setChecked(bool(IMP["sottocartelle"]))
        self.sotto.setVisible(ci_sono_cartelle)
        lay.addWidget(self.sotto)
        riga = QHBoxLayout()
        v = pulsante("Verifica firme", "scudo", "primario")
        e = pulsante("Estrai documenti", "pacco")
        v.clicked.connect(lambda: self._scegli("verifica"))
        e.clicked.connect(lambda: self._scegli("estrai"))
        riga.addWidget(v)
        riga.addWidget(e)
        lay.addLayout(riga)

    def _scegli(self, a):
        self.azione = a
        self.accept()


# ============================================================ UI: LAVORI IN SOTTOFONDO
class Scansione(QThread):
    avanzamento = pyqtSignal(str, int)
    fine = pyqtSignal(list)

    def __init__(self, cartelle, ricorsiva, estensioni, parent=None):
        super().__init__(parent)
        self.cartelle, self.ricorsiva, self.estensioni = cartelle, ricorsiva, estensioni
        self.stop = threading.Event()

    def run(self):
        trovati = []
        for cartella in self.cartelle:
            try:
                if self.ricorsiva:
                    for radice, _d, nomi in os.walk(cartella):
                        if self.stop.is_set():
                            break
                        self.avanzamento.emit(radice, len(trovati))
                        trovati += [os.path.join(radice, n) for n in nomi if supportato(n, self.estensioni)]
                else:
                    trovati += [os.path.join(cartella, n) for n in os.listdir(cartella)
                                if supportato(n, self.estensioni) and os.path.isfile(os.path.join(cartella, n))]
            except OSError:
                pass
        self.fine.emit([] if self.stop.is_set() else trovati)


class Elaborazione(QThread):
    corrente = pyqtSignal(str)
    risultato = pyqtSignal(object)
    errore = pyqtSignal(str)

    def __init__(self, percorsi, estrai=False, verifica=True, cartella_out=None, elimina=False, parent=None):
        super().__init__(parent)
        self.percorsi, self.estrai, self.verifica, self.cartella_out, self.elimina = percorsi, estrai, verifica, cartella_out, elimina
        self.stop = threading.Event()

    def run(self):
        try:
            asyncio.run(self._tutti())
        except Exception:
            testo = traceback.format_exc()
            log_errore(testo)
            self.errore.emit("Errore interno durante l'analisi (dettagli in errori.log)")

    async def _tutti(self):
        sem = asyncio.Semaphore(max(1, int(IMP["concorrenza"])))

        async def uno(path):
            async with sem:
                if self.stop.is_set():
                    return
                self.corrente.emit(os.path.basename(path))
                ris = await analizza_file(path, valida=self.verifica)
                if self.estrai:
                    ris.estr_esito, ris.estr_dettaglio = await asyncio.to_thread(estrai_p7m_su_disco, path, self.cartella_out)
                    # un originale con firma non valida non si cancella mai
                    if self.elimina and ris.estr_esito in ("ok", "duplicato") and ris.stato != "error":
                        try:
                            os.remove(path)
                            ris.originale_eliminato = True
                        except OSError:
                            pass
                self.risultato.emit(ris)

        await asyncio.gather(*(uno(p) for p in self.percorsi))


# ============================================================ UI: ZONA DI RILASCIO
class ZonaRilascio(QWidget):
    scegli_file = pyqtSignal()
    scegli_cartella = pyqtSignal()

    def __init__(self, titolo, sottotitolo, altezza=250, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(altezza)
        self._fase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(33)
        self._timer.timeout.connect(self._passo)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(30, 104, 30, 26)
        lay.setSpacing(6)
        t = etichetta(titolo, "titoloMedio")
        s = etichetta(sottotitolo, "attenuato", True)
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        s.setAlignment(Qt.AlignmentFlag.AlignCenter)
        riga = QHBoxLayout()
        riga.addStretch()
        b1, b2 = pulsante("Scegli i file…", "documento", "primario"), pulsante("Scegli una cartella…", "cartella")
        b1.clicked.connect(self.scegli_file)
        b2.clicked.connect(self.scegli_cartella)
        riga.addWidget(b1)
        riga.addWidget(b2)
        riga.addStretch()
        lay.addWidget(t)
        lay.addWidget(s)
        lay.addSpacing(10)
        lay.addLayout(riga)
        lay.addStretch()

    def _passo(self):
        self._fase = (self._fase + 0.033) % 3600.0
        self.update()

    def showEvent(self, e):
        self._timer.start()
        super().showEvent(e)

    def hideEvent(self, e):
        self._timer.stop()
        super().hideEvent(e)

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        g = QLinearGradient(r.topLeft(), r.bottomRight())
        g.setColorAt(0, QColor(C["zona_a"]))
        g.setColorAt(1, QColor(C["zona_b"]))
        p.setBrush(g)
        penna = QPen(QColor(C["accento"]), 1.6)
        penna.setStyle(Qt.PenStyle.CustomDashLine)
        penna.setDashPattern([6, 5])
        penna.setDashOffset(-self._fase * 14)
        p.setPen(penna)
        p.drawRoundedRect(r, 18, 18)
        cx, cy = r.center().x(), r.top() + 56
        alone = 0.5 + 0.5 * math.sin(self._fase * 3.0)
        p.setPen(Qt.PenStyle.NoPen)
        col = QColor(C["accento"])
        col.setAlpha(int(25 + 35 * alone))
        p.setBrush(col)
        p.drawEllipse(QPointF(cx, cy), 34 + 6 * alone, 34 + 6 * alone)
        p.setBrush(QColor(C["cerchio"]))
        p.drawEllipse(QPointF(cx, cy), 30, 30)
        dy = 3.5 * math.sin(self._fase * 2.2)
        p.drawPixmap(QPointF(cx - 22, cy - 22 + dy), icona("carica", C["accento_chiaro"], 30).pixmap(44, 44))
        p.end()


class OverlayRilascio(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.testo = ""
        self.hide()

    def paintEvent(self, _e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        fondo = QColor(C["sfondo"])
        fondo.setAlpha(225)
        p.fillRect(self.rect(), fondo)
        p.setPen(QPen(QColor(C["accento"]), 2, Qt.PenStyle.DashLine))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawRoundedRect(QRectF(self.rect()).adjusted(20, 20, -20, -20), 18, 18)
        f = p.font()
        f.setPointSize(18)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(C["testo"]))
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.testo)
        p.end()


# ============================================================ UI: TABELLA ESITI
class DelegatoCelle(QStyledItemDelegate):
    """Solo i bordi di colonna: tra una riga e l'altra nessuna linea."""
    ALTEZZA = 34

    def sizeHint(self, opt, idx):
        s = super().sizeHint(opt, idx)
        if not idx.parent().isValid():
            s.setHeight(self.ALTEZZA)
        return s

    def paint(self, p, opt, idx):
        super().paint(p, opt, idx)
        if idx.parent().isValid() or idx.column() == idx.model().columnCount() - 1:
            return
        p.save()
        p.setPen(QColor(C["bordo"]))
        x = opt.rect.right()
        p.drawLine(x, opt.rect.top(), x, opt.rect.bottom())
        p.restore()


class AlberoEsiti(QTreeWidget):
    def drawBranches(self, p, rect, idx):
        if self.selectionModel().isSelected(idx):
            p.fillRect(rect, QColor(C["selezione"]))
        if not idx.parent().isValid() and self.model().hasChildren(idx):
            cx, cy = rect.right() - 11, rect.center().y()
            if self.isExpanded(idx):
                pol = QPolygonF([QPointF(cx - 4, cy - 2), QPointF(cx + 4, cy - 2), QPointF(cx, cy + 3)])
            else:
                pol = QPolygonF([QPointF(cx - 2, cy - 4), QPointF(cx + 3, cy), QPointF(cx - 2, cy + 4)])
            p.save()
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(C["attenuato"]))
            p.drawPolygon(pol)
            p.restore()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.parent() is not None and hasattr(self, "su_resize"):
            self.su_resize()


SIMBOLO = {"ok": "✓", "warn": "!", "error": "✕", "none": "–"}


class PannelloDettaglio(QWidget):
    """Riga espansa: il perche' dell'esito, controllo per controllo, piu' dati completi e azioni."""

    def __init__(self, ris: RisultatoDoc, fi: Optional[FirmaInfo], lotto):
        super().__init__()
        self.interno = QFrame(self)
        self.interno.setObjectName("dettaglio")
        lay = QVBoxLayout(self.interno)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(10)
        colonne = QHBoxLayout()
        colonne.setSpacing(24)
        self._blocchi = []
        colonne.addLayout(self._blocco("CONTROLLI ESEGUITI", self._html_controlli(ris, fi)), 5)
        if fi is not None:
            colonne.addLayout(self._blocco("FIRMATARIO E CERTIFICATO", self._html_firma(fi)), 4)
        colonne.addLayout(self._blocco("DOCUMENTO", self._html_doc(ris)), 4)
        lay.addLayout(colonne)
        azioni = QHBoxLayout()
        azioni.setSpacing(6)

        def agg(testo, ic, fn):
            b = pulsante(testo, ic, "piccolo")
            b.clicked.connect(fn)
            azioni.addWidget(b)

        agg("Apri documento", "apri", lambda: lotto.apri(ris))
        agg("Mostra nella cartella", "cartella", lambda: mostra_in_cartella(ris.percorso))
        if ris.formato == "CAdES" and not ris.errore:
            agg("Estrai…", "scarica", lambda: lotto.estrai_singolo(ris))
        if fi is not None and fi.cert_der:
            agg("Certificato", "certificato", lambda: DialogoCertificato(lotto, fi).exec())
        if ris.fattura:
            agg("Fattura", "fattura", lambda: DialogoFattura(lotto, ris.nome_contenuto or ris.nome, ris.fattura).exec())
        agg("Copia report", "copia", lambda: lotto.copia(report_testuale(ris), "Report copiato negli appunti"))
        azioni.addStretch()
        lay.addLayout(azioni)

    def _blocco(self, titolo, corpo):
        v = QVBoxLayout()
        v.setSpacing(4)
        v.addWidget(etichetta(titolo, "etichetta"))
        l = QLabel(corpo)
        l.setTextFormat(Qt.TextFormat.RichText)
        l.setWordWrap(True)
        l.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        l.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        l.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        v.addWidget(l)
        v.addStretch()
        return v

    @staticmethod
    def _html_controlli(ris, fi):
        if fi is None or not fi.controlli:
            motivo = html.escape((fi.esito if fi else ris.esito) or "Nessun controllo eseguito")
            return f"<span style='color:{C[(fi.stato if fi else ris.stato)]}'>{motivo}</span>"
        r = "".join(f"<tr><td style='color:{C[c.stato]};font-weight:700;padding:1px 8px 3px 0'>{SIMBOLO[c.stato]}</td>"
                    f"<td style='padding:1px 0 3px 0'><b>{html.escape(c.nome)}</b> "
                    f"<span style='color:{C['attenuato']}'>{html.escape(c.dettaglio)}</span></td></tr>" for c in fi.controlli)
        return f"<table cellspacing='0' cellpadding='0'>{r}</table>"

    @staticmethod
    def _kv(coppie):
        r = "".join(f"<tr><td style='color:{C['tenue']};padding:1px 10px 3px 0;white-space:nowrap'>{html.escape(k)}</td>"
                    f"<td style='padding:1px 0 3px 0'>{html.escape(str(v))}</td></tr>" for k, v in coppie if v)
        return f"<table cellspacing='0' cellpadding='0'>{r}</table>"

    def _html_firma(self, f):
        return self._kv([("Tipo", f.tipo + (f" · busta livello {f.livello + 1}" if f.livello else "")), ("Firmatario", f.firmatario),
                         ("Identificativo", f.identificativo), ("Organizzazione", f.organizzazione),
                         ("Data di firma", fmt_dt(f.data_firma) if f.data_firma else "non presente"), ("Fonte della data", f.fonte_data),
                         ("Data /M del PDF", fmt_dt(f.data_pdf_m) if f.data_pdf_m else ""),
                         ("Marca temporale", fmt_dt(f.marca_temporale) if f.marca_temporale else ""), ("TSA", f.marca_tsa),
                         ("Emesso da", f.emittente), ("Seriale", f.seriale),
                         ("Validità", f"{fmt_data(f.valido_dal)} → {fmt_data(f.valido_al)}" if f.valido_dal else ""),
                         ("Motivo", f.motivo), ("Luogo", f.luogo), ("Contatto", f.contatto), ("Campo PDF", f.campo)] + [("Nota", n) for n in f.note])

    def _html_doc(self, r):
        return self._kv([("Percorso", r.percorso.replace("\\", "\\\u200b")), ("Formato", r.formato), ("Dimensione", fmt_size(r.dimensione)),
                         ("Contiene", f"{r.nome_contenuto} ({r.tipo_contenuto})" if r.nome_contenuto and r.tipo_contenuto else r.nome_contenuto),
                         ("Buste annidate", r.livelli + 1 if r.livelli else ""), ("SHA-256", f"{r.sha256[:32]} {r.sha256[32:]}"),
                         ("Estrazione", f"{ETICHETTA_ESTRAZIONE[r.estr_esito]}: {r.estr_dettaglio}" if r.estr_esito else ""),
                         ("Originale", "eliminato dopo l'estrazione" if r.originale_eliminato else "")] + [("Nota", n) for n in r.note])

    def adatta(self, larghezza) -> int:
        self.interno.setFixedWidth(larghezza)
        h = self.interno.layout().totalHeightForWidth(larghezza)
        self.interno.setFixedHeight(h)
        self.setFixedSize(larghezza, h)
        return h


COLONNE_CHI = [("firmatario", "Firmatario", 170), ("id", "Codice fiscale / ID", 170), ("data", "Data e ora firma", 150)]
COLONNE_CERT = [("marca", "Marca temporale", 150), ("scad", "Certificato fino al", 120), ("ca", "Certificatore", 230), ("org", "Organizzazione", 160)]
COLONNE_VERIFICA = [("esito", "Esito", 135), ("doc", "Documento", 230)] + COLONNE_CHI + [("motivo", "Perché", 480)] + COLONNE_CERT + [("fmt", "Formato", 70)]
COLONNE_ESTRAI = [("esito", "Estrazione", 145), ("doc", "File originale", 210), ("estratto", "Estratto come", 170)] + COLONNE_CHI + \
                 [("verifica", "Verifica firma", 105), ("motivo", "Perché", 420)] + COLONNE_CERT


class PannelloLotto(QWidget):
    """Scheda Verifica o Estrazione: una tabella unica, filtri compatti, dettaglio espandibile riga per riga."""
    richiesta_estrazione = pyqtSignal(list)
    messaggio = pyqtSignal(str)

    def __init__(self, modalita):
        super().__init__()
        self.modalita = modalita
        self.estrai = modalita == "estrai"
        self.colonne = COLONNE_ESTRAI if self.estrai else COLONNE_VERIFICA
        self.chiavi = [c[0] for c in self.colonne]
        self.risultati: List[RisultatoDoc] = []
        self.filtro, self.ordine, self.ordine_desc = "all", None, False
        self.tutti_aperti = False
        self.lavoro, self.scan = None, None
        self.totale, self.t0 = 0, 0.0
        self._attesa = []
        self._pannelli = {}
        self.dest = IMP["cartella_output"] or ""
        self._timer_f = QTimer(self)
        self._timer_f.setSingleShot(True)
        self._timer_f.setInterval(200)
        self._timer_f.timeout.connect(self.ripopola)
        self._timer_r = QTimer(self)
        self._timer_r.setSingleShot(True)
        self._timer_r.setInterval(120)
        self._timer_r.timeout.connect(self._adatta_pannelli)
        self._costruisci()
        BUS.tema.connect(self.ripopola)

    # ---- costruzione
    def _costruisci(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 12)
        lay.setSpacing(10)
        testa = QHBoxLayout()
        self.ico_testa = QLabel()
        self._ico_nome = "pacco" if self.estrai else "scudo"
        BUS.tema.connect(self._aggiorna_ico)
        self._aggiorna_ico()
        titoli = QVBoxLayout()
        titoli.setSpacing(0)
        titoli.addWidget(etichetta("Estrazione documenti" if self.estrai else "Verifica firme digitali", "titoloMedio"))
        titoli.addWidget(etichetta("Estrae il contenuto dei .p7m con il nome pulito e mostra chi ha firmato" if self.estrai
                                   else "CAdES (.p7m, .p7s), PAdES (.pdf), XAdES (.xml) e fatture elettroniche", "attenuato"))
        testa.addWidget(self.ico_testa)
        testa.addSpacing(6)
        testa.addLayout(titoli, 1)
        b_file, b_cart = pulsante("Apri file…", "documento", "primario"), pulsante("Apri cartella…", "cartella")
        b_file.clicked.connect(self.scegli_file)
        b_cart.clicked.connect(self.scegli_cartella)
        self.b_report = pulsante("Report", "tabella")
        m = QMenu(self)
        m.addAction("Esporta CSV…", lambda: self._salva_report(".csv"))
        m.addAction("Esporta HTML…", lambda: self._salva_report(".html"))
        self.b_report.setMenu(m)
        self.b_svuota = pulsante("Svuota", "cestino", "pericolo")
        self.b_svuota.clicked.connect(self.svuota)
        testa.addWidget(b_file)
        testa.addWidget(b_cart)
        if not self.estrai:
            self.b_estrai = pulsante("Estrai documenti", "scarica", suggerimento="Estrae i .p7m selezionati, o tutti se non ne selezioni")
            self.b_estrai.clicked.connect(self._estrai_da_verifica)
            testa.addWidget(self.b_estrai)
        testa.addWidget(self.b_report)
        testa.addWidget(self.b_svuota)
        lay.addLayout(testa)

        if self.estrai:
            opz = QHBoxLayout()
            opz.addWidget(etichetta("Destinazione:", "attenuato"))
            self.lbl_dest = etichetta("", None)
            opz.addWidget(self.lbl_dest)
            b1, b2 = pulsante("Scegli cartella…", "cartella", "piccolo"), pulsante("Accanto agli originali", None, "piccolo fantasma")
            b1.clicked.connect(self._scegli_dest)
            b2.clicked.connect(lambda: self._imposta_dest(""))
            opz.addWidget(b1)
            opz.addWidget(b2)
            opz.addStretch()
            self.chk_verifica = QCheckBox("Verifica anche le firme")
            self.chk_verifica.setToolTip("Se la togli, l'estrazione è più veloce: restano i dati del firmatario ma senza esito")
            self.chk_verifica.setChecked(bool(IMP["verifica_in_estrazione"]))
            self.chk_verifica.toggled.connect(self._salva_verifica)
            opz.addWidget(self.chk_verifica)
            lay.addLayout(opz)
            self._imposta_dest(self.dest)

        filtri = QHBoxLayout()
        filtri.setSpacing(4)
        self.gruppo = QButtonGroup(self)
        self.gruppo.setExclusive(True)
        self.chip = {}
        voci = ([("all", "Tutti"), ("ok", "Estratti"), ("duplicato", "Già presenti"), ("errore", "Falliti")] if self.estrai else
                [("all", "Tutti"), ("ok", "Verificati"), ("warn", "Attenzione"), ("error", "Non validi"), ("none", "Senza firma")])
        self.voci = dict(voci)
        for k, t in voci:
            b = pulsante(f"{t}  0", None, "filtro")
            b.setCheckable(True)
            b.setChecked(k == "all")
            b.clicked.connect(lambda _c=False, kk=k: self._imposta_filtro(kk))
            self.gruppo.addButton(b)
            self.chip[k] = b
            filtri.addWidget(b)
        filtri.addSpacing(10)
        self.cerca = QLineEdit()
        self.cerca.setPlaceholderText("Filtra per file, firmatario o codice fiscale…")
        self.cerca.setClearButtonEnabled(True)
        self.cerca.setAcceptDrops(False)
        self.cerca.textChanged.connect(lambda: self._timer_f.start())
        filtri.addWidget(self.cerca, 1)
        b = pulsante("Espandi / comprimi", "espandi", "fantasma")
        b.clicked.connect(self.alterna_tutti)
        filtri.addWidget(b)
        lay.addLayout(filtri)

        self.riga_av = QWidget()
        av = QHBoxLayout(self.riga_av)
        av.setContentsMargins(0, 0, 0, 0)
        self.lbl_stato = etichetta("", "attenuato")
        self.barra = QProgressBar()
        self.barra.setFixedWidth(240)
        self.b_annulla = pulsante("Annulla", "chiudi", "piccolo pericolo")
        self.b_annulla.clicked.connect(self.annulla)
        av.addWidget(self.lbl_stato, 1)
        av.addWidget(self.barra)
        av.addWidget(self.b_annulla)
        self.riga_av.hide()
        lay.addWidget(self.riga_av)

        self.pila = QStackedWidget()
        self.zona = ZonaRilascio("Trascina qui i .p7m da estrarre" if self.estrai else "Trascina qui i documenti firmati",
                                 "File o cartelle intere: la tabella si riempie mentre lavoro.")
        self.zona.scegli_file.connect(self.scegli_file)
        self.zona.scegli_cartella.connect(self.scegli_cartella)
        self.pila.addWidget(self.zona)
        self.t = AlberoEsiti()
        self.t.setColumnCount(len(self.colonne))
        self.t.setHeaderLabels([c[1] for c in self.colonne])
        h = self.t.header()
        h.setStretchLastSection(True)
        h.setSectionsMovable(True)
        h.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        h.setSectionsClickable(True)
        h.setHighlightSections(False)
        h.sectionClicked.connect(self._ordina)
        for i, c in enumerate(self.colonne):
            self.t.setColumnWidth(i, c[2])
        salvate = IMP["colonne_estrai" if self.estrai else "colonne_verifica"]
        if salvate:
            try:
                h.restoreState(QByteArray.fromHex(salvate.encode()))
            except Exception:
                pass
        self.t.setItemDelegate(DelegatoCelle(self.t))
        self.t.setIndentation(22)
        self.t.setUniformRowHeights(False)
        self.t.setAllColumnsShowFocus(True)
        self.t.setExpandsOnDoubleClick(False)
        self.t.setIconSize(QSize(10, 10))
        self.t.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.t.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.t.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.t.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.t.customContextMenuRequested.connect(self._menu)
        self.t.itemExpanded.connect(self._su_espansa)
        self.t.itemCollapsed.connect(self._su_chiusa)
        self.t.itemDoubleClicked.connect(lambda it, _c: it.setExpanded(not it.isExpanded()) if it.parent() is None else None)
        self.t.su_resize = lambda: self._timer_r.start()
        self.pila.addWidget(self.t)
        lay.addWidget(self.pila, 1)
        self._aggiorna_azioni()

    def _aggiorna_ico(self):
        self.ico_testa.setPixmap(icona(self._ico_nome, C["ok"], 26).pixmap(30, 30))

    def _salva_verifica(self, v):
        IMP["verifica_in_estrazione"] = bool(v)
        IMP.salva()

    def _imposta_dest(self, c):
        self.dest = c
        self.lbl_dest.setText(c or "accanto ai file originali")

    def _scegli_dest(self):
        c = QFileDialog.getExistingDirectory(self, "Cartella di destinazione", self.dest or IMP["ultima_cartella"] or "")
        if c:
            self._imposta_dest(c)

    def salva_colonne(self):
        IMP["colonne_estrai" if self.estrai else "colonne_verifica"] = bytes(self.t.header().saveState().toHex()).decode()

    # ---- ingresso dei file
    @property
    def _estensioni(self):
        return ESTENSIONI_ESTRAI if self.estrai else ESTENSIONI_VERIFICA

    def scegli_file(self):
        filtro = "Buste P7M (*.p7m *.P7M *.p7m*)" if self.estrai else "Documenti firmati (*.p7m *.p7s *.pdf *.xml *.p7m*)"
        percorsi, _ = QFileDialog.getOpenFileNames(self, "Scegli i documenti", IMP["ultima_cartella"] or "", filtro + ";;Tutti i file (*)")
        if percorsi:
            IMP["ultima_cartella"] = os.path.dirname(percorsi[0])
            IMP.salva()
            self.carica(percorsi, [], True)

    def scegli_cartella(self):
        c = QFileDialog.getExistingDirectory(self, "Scegli una cartella", IMP["ultima_cartella"] or "")
        if c:
            IMP["ultima_cartella"] = c
            IMP.salva()
            self.carica([], [c], bool(IMP["sottocartelle"]))

    def occupato(self):
        return bool((self.lavoro and self.lavoro.isRunning()) or (self.scan and self.scan.isRunning()))

    def carica(self, files, cartelle, ricorsiva):
        if self.occupato():
            avviso(self, "Attendi", "C'è già un'operazione in corso in questa scheda.", "warn")
            return
        files = [f for f in files if supportato(os.path.basename(f), self._estensioni) or not self.estrai]
        if cartelle:
            self._attesa = files
            self.scan = Scansione(cartelle, ricorsiva, self._estensioni, self)
            self.scan.avanzamento.connect(lambda p, n: self.lbl_stato.setText(f"Cerco i file… {n} trovati · {tronca(p, 80)}"))
            self.scan.fine.connect(self._fine_scansione)
            self.lbl_stato.setText("Cerco i file…")
            self.barra.setRange(0, 0)
            self.riga_av.show()
            self.scan.start()
        else:
            self.avvia(files)

    def _fine_scansione(self, trovati):
        self.barra.setRange(0, 100)
        self.riga_av.hide()
        tutti = list(dict.fromkeys(self._attesa + trovati))
        if not tutti:
            if not self.scan.stop.is_set():
                avviso(self, "Nessun file", "Nessun documento supportato trovato.", "warn")
            return
        self.avvia(tutti)

    def avvia(self, percorsi):
        gia = {r.percorso for r in self.risultati}
        percorsi = [p for p in percorsi if p not in gia]
        if not percorsi:
            avviso(self, "Nessun file da elaborare", "I documenti scelti non sono supportati o sono già in tabella.", "warn")
            return
        elimina = False
        if self.estrai and IMP["elimina_originale"]:
            elimina = conferma(self, "Eliminare gli originali?", "Dopo ogni estrazione riuscita il .p7m originale verrà ELIMINATO definitivamente "
                               "(mai se la firma risulta non valida). Confermi?")
        self.totale, self.fatti, self.t0 = len(percorsi), 0, time.time()
        self.lavoro = Elaborazione(percorsi, estrai=self.estrai, verifica=(not self.estrai) or self.chk_verifica.isChecked(),
                                   cartella_out=(self.dest or None) if self.estrai else None, elimina=elimina, parent=self)
        self.lavoro.corrente.connect(lambda n: self.lbl_stato.setText(f"In corso: {tronca(n, 80)}"))
        self.lavoro.risultato.connect(self._su_risultato)
        self.lavoro.errore.connect(lambda m: avviso(self, "Errore", m, "error"))
        self.lavoro.finished.connect(self._fine)
        self.barra.setRange(0, self.totale)
        self.barra.setValue(0)
        self.barra.setFormat(f"%v / {self.totale}")
        self.riga_av.show()
        self.b_annulla.setEnabled(True)
        self.pila.setCurrentWidget(self.t)
        self._aggiorna_azioni()
        self.lavoro.start()

    def annulla(self):
        if self.scan and self.scan.isRunning():
            self.scan.stop.set()
        if self.lavoro and self.lavoro.isRunning():
            self.lavoro.stop.set()
        self.b_annulla.setEnabled(False)

    def ferma_e_attendi(self):
        for w in (self.scan, self.lavoro):
            if w and w.isRunning():
                w.stop.set()
                w.wait(4000)

    def _su_risultato(self, ris):
        self.risultati.append(ris)
        self.fatti += 1
        self.barra.setValue(self.fatti)
        self._aggiorna_conteggi()
        if self.ordine is None:
            if self._passa_filtro(ris):
                self._aggiungi_righe(ris)
        else:
            self._timer_f.start()

    def _fine(self):
        trascorso = time.time() - self.t0
        annullato = self.lavoro.stop.is_set()
        self.riga_av.hide()
        self._aggiorna_azioni()
        self.ripopola()
        self.messaggio.emit(f"{'Annullato' if annullato else 'Completato'}: {self.fatti} documenti in {trascorso:.1f} s")
        if len(self.risultati) == 1 and self.t.topLevelItemCount():
            self.t.topLevelItem(0).setExpanded(True)

    def svuota(self):
        if self.occupato():
            return
        self.risultati = []
        self.ripopola()
        self._aggiorna_conteggi()
        self._aggiorna_azioni()

    def _aggiorna_azioni(self):
        attivo = bool(self.risultati) and not self.occupato()
        self.b_report.setEnabled(attivo)
        self.b_svuota.setEnabled(attivo)
        if not self.estrai:
            self.b_estrai.setEnabled(attivo and any(r.formato == "CAdES" and not r.errore for r in self.risultati))
        self.pila.setCurrentWidget(self.t if (self.risultati or self.occupato()) else self.zona)

    # ---- filtri / ordinamento
    def _chiave_filtro(self, r):
        if self.estrai:
            return "errore" if r.estr_esito == "permessi" else r.estr_esito
        return r.stato

    def _aggiorna_conteggi(self):
        n = {k: 0 for k in self.chip}
        n["all"] = len(self.risultati)
        for r in self.risultati:
            k = self._chiave_filtro(r)
            if k in n:
                n[k] += 1
        for k, b in self.chip.items():
            b.setText(f"{self.voci[k]}  {n[k]}")

    def _imposta_filtro(self, k):
        self.filtro = k
        self.ripopola()

    def _passa_filtro(self, r):
        if self.filtro != "all" and self._chiave_filtro(r) != self.filtro:
            return False
        q = self.cerca.text().strip().lower()
        if q:
            mucchio = (r.nome + " " + r.nome_contenuto + " " + " ".join(f"{f.firmatario} {f.identificativo} {f.organizzazione}" for f in r.firme)).lower()
            return q in mucchio
        return True

    def _ordina(self, indice):
        chiave = self.chiavi[indice]
        if self.ordine == chiave:
            self.ordine_desc = not self.ordine_desc
        else:
            self.ordine, self.ordine_desc = chiave, False
        h = self.t.header()
        h.setSortIndicatorShown(True)
        h.setSortIndicator(indice, Qt.SortOrder.DescendingOrder if self.ordine_desc else Qt.SortOrder.AscendingOrder)
        self.ripopola()

    def _valore_ordine(self, r):
        f = r.firme[0] if r.firme else None
        k = self.ordine

        def ts(d):
            try:
                return d.timestamp() if d else 0
            except Exception:
                return 0
        if k == "esito":
            return (r.estr_esito if self.estrai else -ORDINE_STATO[r.stato])
        if k == "doc":
            return r.nome.lower()
        if k == "estratto":
            return os.path.basename(r.estr_dettaglio).lower()
        if k == "fmt":
            return r.formato
        if k == "verifica":
            return ORDINE_STATO[r.stato]
        if k == "motivo":
            return (f.esito if f else r.esito).lower()
        if f is None:
            return 0 if k in ("data", "marca", "scad") else ""
        return {"firmatario": f.firmatario.lower(), "id": f.identificativo, "org": f.organizzazione.lower(), "data": ts(f.data_firma),
                "marca": ts(f.marca_temporale), "scad": ts(f.valido_al), "ca": f.emittente.lower()}[k]

    # ---- righe
    def ripopola(self):
        aperti = set()
        for i in range(self.t.topLevelItemCount()):
            it = self.t.topLevelItem(i)
            if it.isExpanded():
                aperti.add(self._id_riga(it))
        for _f, p in self._pannelli.values():
            p.hide()
        self._pannelli.clear()
        self.t.setUpdatesEnabled(False)
        self.t.clear()
        lista = [r for r in self.risultati if self._passa_filtro(r)]
        if self.ordine:
            lista.sort(key=self._valore_ordine, reverse=self.ordine_desc)
        for r in lista:
            self._aggiungi_righe(r, aperti)
        self.t.setUpdatesEnabled(True)
        self._aggiorna_azioni()

    @staticmethod
    def _id_riga(it):
        r, f = it.data(0, Qt.ItemDataRole.UserRole)
        return (r.percorso, id(f))

    @staticmethod
    def _breve(d):
        return dt_locale(d).strftime("%d/%m/%Y %H:%M:%S")

    def _testi(self, r, f, primo):
        v = {"doc": r.nome if primo else "↳", "fmt": r.formato if primo else "", "motivo": (f.esito if f else r.esito)}
        if f is not None:
            v.update(firmatario=(f.firmatario + (" (controfirma)" if f.tipo == "Controfirma" else "")), org=f.organizzazione,
                     id=re.sub(r"^TINIT-", "", f.identificativo), ca=f.emittente,
                     data=self._breve(f.data_firma) if f.data_firma else "non presente",
                     marca=(self._breve(f.marca_temporale) if f.marca_temporale else "—"), scad=fmt_data(f.valido_al) if f.valido_al else "")
        if self.estrai:
            if primo:
                v["estratto"] = os.path.basename(r.estr_dettaglio) if r.estr_esito in ("ok", "duplicato") else ""
            v["esito"] = ETICHETTA_ESTRAZIONE[r.estr_esito] if primo else ""
            v["verifica"] = etichetta_firma(f) if f else etichetta_doc(r)
            if r.estr_esito in ("errore", "permessi") and primo:
                v["motivo"] = r.estr_dettaglio
        else:
            v["esito"] = etichetta_firma(f) if f else etichetta_doc(r)
        return v

    def _colore_esito(self, r, f, primo):
        if self.estrai:
            if not primo:
                return None
            return {"ok": C["ok"], "duplicato": C["info"]}.get(r.estr_esito, C["error"])
        return C[f.stato if f else r.stato]

    def _aggiungi_righe(self, r, aperti=()):
        for i, f in enumerate(r.firme or [None]):
            primo = i == 0
            it = QTreeWidgetItem()
            it.setData(0, Qt.ItemDataRole.UserRole, (r, f))
            testi = self._testi(r, f, primo)
            for c, k in enumerate(self.chiavi):
                t = testi.get(k, "")
                it.setText(c, t)
                if t and k in ("doc", "motivo", "firmatario", "ca", "org", "estratto"):
                    it.setToolTip(c, r.percorso if k == "doc" else (r.estr_dettaglio if k == "estratto" else t))
            colore = self._colore_esito(r, f, primo)
            if colore:
                it.setIcon(0, pallino(colore))
                it.setForeground(0, QColor(colore))
            if "verifica" in self.chiavi:
                it.setForeground(self.chiavi.index("verifica"), QColor(C[f.stato if f else r.stato]))
            if not primo:
                it.setForeground(1, QColor(C["tenue"]))
            self.t.addTopLevelItem(it)
            figlio = QTreeWidgetItem(it)
            figlio.setFlags(Qt.ItemFlag.ItemIsEnabled)
            figlio.setFirstColumnSpanned(True)
            if (r.percorso, id(f)) in aperti or (self.tutti_aperti and self.t.topLevelItemCount() <= 300):
                it.setExpanded(True)

    def _larghezza_dettaglio(self):
        return max(self.t.viewport().width() - self.t.indentation() - 8, 620)

    def _su_espansa(self, it):
        if it.parent() is not None or it.childCount() == 0:
            return
        r, f = it.data(0, Qt.ItemDataRole.UserRole)
        figlio = it.child(0)
        p = PannelloDettaglio(r, f, self)
        figlio.setSizeHint(0, QSize(0, p.adatta(self._larghezza_dettaglio())))
        self.t.setItemWidget(figlio, 0, p)
        self._pannelli[id(figlio)] = (figlio, p)

    def _su_chiusa(self, it):
        if it.parent() is None and it.childCount():
            figlio = it.child(0)
            w = self.t.itemWidget(figlio, 0)
            if w is not None:
                w.hide()             # deleteLater agisce solo al giro dopo: intanto non deve restare visibile
            self.t.removeItemWidget(figlio, 0)
            self._pannelli.pop(id(figlio), None)

    def _adatta_pannelli(self):
        l = self._larghezza_dettaglio()
        for figlio, p in self._pannelli.values():
            figlio.setSizeHint(0, QSize(0, p.adatta(l)))

    def alterna_tutti(self):
        self.tutti_aperti = not self.tutti_aperti
        n = min(self.t.topLevelItemCount(), 300) if self.tutti_aperti else self.t.topLevelItemCount()
        for i in range(n):
            self.t.topLevelItem(i).setExpanded(self.tutti_aperti)
        if self.tutti_aperti and self.t.topLevelItemCount() > 300:
            self.messaggio.emit("Espanse le prime 300 righe")

    def _selezionati(self):
        visti, out = set(), []
        for it in self.t.selectedItems():
            if it.parent() is None:
                r, _f = it.data(0, Qt.ItemDataRole.UserRole)
                if r.percorso not in visti:
                    visti.add(r.percorso)
                    out.append(r)
        return out

    def _menu(self, pos):
        it = self.t.itemAt(pos)
        if it is None or it.parent() is not None:
            return
        r, f = it.data(0, Qt.ItemDataRole.UserRole)
        m = QMenu(self)
        m.addAction("Mostra dettagli", lambda: it.setExpanded(True))
        m.addAction("Apri documento", lambda: self.apri(r))
        m.addAction("Mostra nella cartella", lambda: mostra_in_cartella(r.percorso))
        if r.formato == "CAdES" and not r.errore:
            m.addAction("Estrai…", lambda: self.estrai_singolo(r))
        m.addSeparator()
        if f is not None and f.cert_der:
            m.addAction("Certificato…", lambda: DialogoCertificato(self, f).exec())
            m.addAction("Copia impronta del certificato", lambda: self.copia(hashlib.sha256(f.cert_der).hexdigest().upper()))
        if f is not None:
            m.addAction("Copia firmatario", lambda: self.copia(f.firmatario))
        m.addAction("Copia report", lambda: self.copia(report_testuale(r), "Report copiato negli appunti"))
        m.exec(self.t.viewport().mapToGlobal(pos))

    # ---- azioni
    def copia(self, testo, msg="Copiato negli appunti"):
        QApplication.clipboard().setText(testo)
        self.messaggio.emit(msg)

    def apri(self, r: RisultatoDoc):
        try:
            if r.formato == "CAdES" and not r.errore and not (r.estr_esito in ("ok", "duplicato") and r.originale_eliminato):
                dati = leggi_contenuto_p7m(r.percorso)
                tmp = os.path.join(tempfile.gettempdir(), f"p7m_{r.sha256[:8]}_{r.nome_contenuto or 'documento'}")
                with open(tmp, 'wb') as f:
                    f.write(dati)
                apri_con_sistema(tmp)
            elif r.estr_esito in ("ok", "duplicato"):
                apri_con_sistema(r.estr_dettaglio)
            else:
                apri_con_sistema(r.percorso)
        except Exception as e:
            avviso(self, "Errore", f"Impossibile aprire il file: {e}", "error")

    def estrai_singolo(self, r: RisultatoDoc):
        iniziale = os.path.join(os.path.dirname(r.percorso), r.nome_contenuto or pulisci_nome_file_globale(r.nome))
        p, _ = QFileDialog.getSaveFileName(self, "Salva documento estratto", iniziale)
        if not p:
            return
        try:
            with open(p, 'wb') as f:
                f.write(leggi_contenuto_p7m(r.percorso))
            self.messaggio.emit("Documento estratto")
        except PermissionError:
            avviso(self, "Errore permessi", "Non hai i permessi per scrivere in questa posizione.", "error")
        except Exception as e:
            avviso(self, "Errore", f"Estrazione non riuscita: {e}", "error")

    def _estrai_da_verifica(self):
        lista = [r.percorso for r in (self._selezionati() or self.risultati) if r.formato == "CAdES" and not r.errore]
        if lista:
            self.richiesta_estrazione.emit(lista)

    def _salva_report(self, ext):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filtro = "CSV (Excel) (*.csv)" if ext == ".csv" else "Pagina HTML (*.html)"
        p, _ = QFileDialog.getSaveFileName(self, "Salva report", f"Report_{self.modalita}_{ts}{ext}", filtro)
        if not p:
            return
        try:
            (esporta_csv if ext == ".csv" else esporta_html)(self.risultati, p)
            self.messaggio.emit("Report salvato")
            if ext == ".html":
                apri_con_sistema(p)
        except PermissionError:
            avviso(self, "Errore permessi", "Non hai i permessi per scrivere in questa posizione.", "error")
        except Exception as e:
            avviso(self, "Errore", f"Salvataggio non riuscito: {e}", "error")


# ============================================================ UI: SCHERMATA INIZIO
class CartaAzione(QFrame):
    def __init__(self, nome_icona, titolo, formato, passi, bottoni):
        super().__init__()
        self.setObjectName("carta")
        self.nome_icona, self.passi = nome_icona, passi
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 16)
        lay.setSpacing(8)
        testa = QHBoxLayout()
        self.ico = QLabel()
        testa.addWidget(self.ico)
        testa.addSpacing(4)
        testa.addWidget(etichetta(titolo, "titoloMedio"), 1)
        self.fmt = etichetta(formato, None, True)
        self.istr = QLabel()
        self.istr.setWordWrap(True)
        self.istr.setTextFormat(Qt.TextFormat.RichText)
        lay.addLayout(testa)
        lay.addWidget(self.fmt)
        lay.addWidget(self.istr, 1)
        riga = QHBoxLayout()
        for t, ic, fn in bottoni:
            b = pulsante(t, ic, "piccolo")
            b.clicked.connect(fn)
            riga.addWidget(b)
        riga.addStretch()
        lay.addLayout(riga)
        BUS.tema.connect(self.aggiorna)
        self.aggiorna()

    def aggiorna(self):
        self.ico.setPixmap(icona(self.nome_icona, C["accento"], 22).pixmap(26, 26))
        self.fmt.setStyleSheet(f"color:{C['accento_chiaro']};font-weight:600;font-size:12px")
        righe = "".join(f"<tr><td style='color:{C['accento']};font-weight:700;padding:0 8px 4px 0'>{i}</td>"
                        f"<td style='color:{C['attenuato']};padding:0 0 4px 0'>{html.escape(t)}</td></tr>" for i, t in enumerate(self.passi, 1))
        self.istr.setText(f"<table cellspacing='0' cellpadding='0'>{righe}</table>")


class SchedaInizio(QScrollArea):
    def __init__(self, app):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        contenuto = QWidget()
        contenuto.setObjectName("sfondo")
        self.setWidget(contenuto)
        esterno = QHBoxLayout(contenuto)
        esterno.setContentsMargins(24, 22, 24, 26)
        colonna = QWidget()
        colonna.setMaximumWidth(1120)
        esterno.addStretch()
        esterno.addWidget(colonna, 100)
        esterno.addStretch()
        lay = QVBoxLayout(colonna)
        lay.setSpacing(16)
        lay.addWidget(etichetta("Benvenuto", "titolo"))
        lay.addWidget(etichetta("Verifica le firme digitali ed estrai i documenti dalle buste .p7m, uno alla volta o a migliaia. "
                                "I file restano sul tuo computer.", "sottotitolo", True))
        zona = ZonaRilascio("Trascina qui i documenti firmati", "File o cartelle: .p7m, .p7s, PDF firmati, XML e fatture elettroniche. Poi scegli se verificare o estrarre.")
        zona.scegli_file.connect(app.scegli_file_inizio)
        zona.scegli_cartella.connect(app.scegli_cartella_inizio)
        lay.addWidget(zona)
        lay.addSpacing(4)
        lay.addWidget(etichetta("COSA VUOI FARE?", "etichetta"))
        v, e = app.verifica, app.estrazione
        carte = [
            ("scudo", "Verifica firme", ".p7m · .p7s · .pdf · .xml",
             ["Scegli i file o un'intera cartella.", "Integrità, catena, revoca e marca temporale per ogni firma.", "Espandi una riga per sapere il perché dell'esito."],
             [("File…", "documento", lambda: (app.vai(v), v.scegli_file())), ("Cartella…", "cartella", lambda: (app.vai(v), v.scegli_cartella()))]),
            ("pacco", "Estrai documenti", "Buste .p7m, anche annidate o in base64",
             ["Scegli i .p7m o una cartella.", "Ogni documento esce con il nome pulito: niente più «.pdf (1) (1).p7m».", "In tabella vedi chi ha firmato e l'esito della verifica."],
             [("File…", "documento", lambda: (app.vai(e), e.scegli_file())), ("Cartella…", "cartella", lambda: (app.vai(e), e.scegli_cartella()))]),
            ("fattura", "Fatture elettroniche", "FatturaPA .xml e .xml.p7m",
             ["Apri la fattura nella verifica.", "Espandi la riga e premi «Fattura».", "Cedente, numero, data e importo in un colpo d'occhio."],
             [("Apri fattura…", "documento", lambda: (app.vai(v), v.scegli_file()))]),
            ("certificato", "Certificati e fiducia", "Trusted List AgID · archivio di Windows",
             ["La Trusted List si aggiorna a ogni avvio.", "Dal dettaglio apri o esporti ogni certificato.", "Le CA private si aggiungono nelle Impostazioni."],
             [("Impostazioni", "ingranaggio", lambda: app.vai(app.impostazioni))]),
        ]
        griglia = QGridLayout()
        griglia.setSpacing(12)
        for i, (ic, t, f, p, b) in enumerate(carte):
            griglia.addWidget(CartaAzione(ic, t, f, p, b), i // 2, i % 2)
        lay.addLayout(griglia)
        lay.addStretch()


# ============================================================ UI: SCHEDA IMPOSTAZIONI
class SchedaImpostazioni(QScrollArea):
    TEMI = {"Sistema": "System", "Chiaro": "Light", "Scuro": "Dark"}
    cambiate = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        cont = QWidget()
        cont.setObjectName("sfondo")
        self.setWidget(cont)
        est = QHBoxLayout(cont)
        est.setContentsMargins(24, 22, 24, 26)
        col = QWidget()
        col.setMaximumWidth(820)
        est.addStretch()
        est.addWidget(col, 100)
        est.addStretch()
        self.lay = QVBoxLayout(col)
        self.lay.setSpacing(10)
        self.lay.addWidget(etichetta("Impostazioni", "titolo"))
        self.lay.addWidget(etichetta("Le modifiche si salvano da sole.", "attenuato"))

        self._sezione("ASPETTO")
        self.tema = QComboBox()
        self.tema.addItems(self.TEMI)
        inv = {v: k for k, v in self.TEMI.items()}
        self.tema.setCurrentText(inv.get(IMP["tema"], "Sistema"))
        self.tema.currentTextChanged.connect(self._cambia_tema)
        self._riga("Tema", self.tema)

        self._sezione("VERIFICA")
        self._opzione("revoca", "Controllo revoca OCSP / CRL", "Interroga online lo stato dei certificati. Se i server non rispondono l'esito diventa «Attenzione» e il motivo è indicato.")
        self._opzione("valida_data_firma", "Valuta i certificati scaduti alla data di firma dichiarata", "Senza marca temporale il risultato resta «Attenzione»: la data dichiarata non è opponibile.")
        self.conc = QComboBox()
        self.conc.addItems([str(n) for n in range(1, 9)])
        self.conc.setCurrentText(str(int(IMP["concorrenza"])))
        self.conc.currentTextChanged.connect(lambda v: self._salva("concorrenza", int(v)))
        self._riga("File elaborati in parallelo", self.conc)

        self._sezione("ESTRAZIONE")
        self._opzione("estrai_annidati", "Apri le buste annidate", "Se un .p7m contiene un altro .p7m (doppia firma) estrae direttamente il documento finale.")
        self._opzione("elimina_originale", "Elimina il .p7m dopo l'estrazione riuscita", "Viene chiesta conferma a ogni lotto. Gli originali con firma non valida non vengono mai eliminati.")
        self._opzione("sottocartelle", "Includi le sottocartelle quando scegli una cartella", "")
        r = QHBoxLayout()
        self.out = QLineEdit(IMP["cartella_output"])
        self.out.setPlaceholderText("Vuoto = accanto ai file originali")
        self.out.editingFinished.connect(lambda: self._salva("cartella_output", self.out.text().strip()))
        b = pulsante("Sfoglia…", "cartella")
        b.clicked.connect(self._sfoglia)
        r.addWidget(self.out, 1)
        r.addWidget(b)
        self._blocco("Cartella di destinazione predefinita", r)

        self._sezione("RADICI ATTENDIBILI")
        r = QHBoxLayout()
        self.lbl_radici = etichetta("", "attenuato", True)
        ba, br, bt = pulsante("Aggiungi CA…", "certificato"), pulsante("Rimuovi aggiunte", None, "pericolo"), pulsante("Aggiorna Trusted List", "aggiorna")
        ba.clicked.connect(self._aggiungi)
        br.clicked.connect(self._azzera)
        bt.clicked.connect(self._aggiorna_tsl)
        r.addWidget(ba)
        r.addWidget(br)
        r.addWidget(bt)
        r.addStretch()
        self._blocco("", r, self.lbl_radici)
        self.lay.addStretch()
        BUS.tsl.connect(self.aggiorna_radici)
        self.aggiorna_radici()

    def _sezione(self, t):
        self.lay.addSpacing(8)
        self.lay.addWidget(etichetta(t, "etichetta"))

    def _carta(self):
        f = QFrame()
        f.setObjectName("pannello")
        self.lay.addWidget(f)
        return f

    def _riga(self, testo, w):
        l = QHBoxLayout(self._carta())
        l.setContentsMargins(14, 10, 14, 10)
        l.addWidget(etichetta(testo), 1)
        l.addWidget(w)

    def _opzione(self, chiave, titolo, descr):
        l = QVBoxLayout(self._carta())
        l.setContentsMargins(14, 10, 14, 10)
        l.setSpacing(2)
        c = QCheckBox(titolo)
        c.setChecked(bool(IMP[chiave]))
        c.toggled.connect(lambda v, k=chiave: self._salva(k, bool(v)))
        l.addWidget(c)
        if descr:
            l.addWidget(etichetta(descr, "attenuato", True))

    def _blocco(self, titolo, riga, extra=None):
        l = QVBoxLayout(self._carta())
        l.setContentsMargins(14, 10, 14, 10)
        if titolo:
            l.addWidget(etichetta(titolo))
        if extra is not None:
            l.addWidget(extra)
        l.addLayout(riga)

    def _salva(self, k, v):
        IMP[k] = v
        IMP.salva()
        ARCHIVIO.cache_validazione.clear()
        self.cambiate.emit()

    def _cambia_tema(self, t):
        IMP["tema"] = self.TEMI[t]
        IMP.salva()
        applica_tema()

    def _sfoglia(self):
        c = QFileDialog.getExistingDirectory(self, "Cartella di destinazione", self.out.text())
        if c:
            self.out.setText(c)
            self._salva("cartella_output", c)

    def aggiorna_radici(self):
        self.lbl_radici.setText(f"{len(ARCHIVIO.radici)} radici attendibili, di cui {len(IMP['radici_extra'])} file di CA aggiunti da te.\n"
                                f"{ARCHIVIO.tsl_descrizione or 'Trusted List AgID non disponibile'}")

    def _aggiungi(self):
        percorsi, _ = QFileDialog.getOpenFileNames(self, "Certificati CA", "", "Certificati (*.cer *.crt *.pem *.der)")
        extra = list(IMP["radici_extra"])
        for p in percorsi:
            try:
                ArchivioFiducia._carica_file(p)
                if p not in extra:
                    extra.append(p)
            except Exception:
                avviso(self, "File non valido", f"{os.path.basename(p)} non è un certificato X.509 valido.", "error")
        if extra != IMP["radici_extra"]:
            IMP["radici_extra"] = extra
            IMP.salva()
            ARCHIVIO.ricarica()
            self.aggiorna_radici()
            self.cambiate.emit()

    def _azzera(self):
        if IMP["radici_extra"]:
            IMP["radici_extra"] = []
            IMP.salva()
            ARCHIVIO.ricarica()
            self.aggiorna_radici()
            self.cambiate.emit()

    def _aggiorna_tsl(self):
        scarica_tsl_in_sottofondo()


def scarica_tsl_in_sottofondo():
    def lavoro():
        ARCHIVIO.ricarica(True)
        BUS.tsl.emit()
    threading.Thread(target=lavoro, daemon=True).start()


# ============================================================ APP PRINCIPALE
class Finestra(QMainWindow):
    def __init__(self, percorsi_avvio=None):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION} · Verifica ed estrazione firme digitali")
        self.setWindowIcon(icona_app())
        self.resize(1320, 860)
        self.setMinimumSize(980, 640)
        self.setAcceptDrops(True)
        centro = QWidget()
        centro.setObjectName("sfondo")
        self.setCentralWidget(centro)
        lay = QVBoxLayout(centro)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        barra = QWidget()
        barra.setObjectName("barraTitolo")
        bl = QHBoxLayout(barra)
        bl.setContentsMargins(16, 10, 16, 10)
        logo = QLabel()
        logo.setPixmap(icona_app().pixmap(30, 30))
        bl.addWidget(logo)
        bl.addSpacing(4)
        bl.addWidget(etichetta("P7M Reader", "marchio"))
        bl.addWidget(etichetta(f"v{APP_VERSION}", "versione"))
        bl.addStretch()
        self.b_tema = pulsante("", "luna", "fantasma", "Cambia tema chiaro / scuro")
        self.b_tema.clicked.connect(self.alterna_tema)
        bl.addWidget(self.b_tema)
        lay.addWidget(barra)

        self.verifica = PannelloLotto("verifica")
        self.estrazione = PannelloLotto("estrai")
        self.impostazioni = SchedaImpostazioni()
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.tabBar().setDrawBase(False)
        self.inizio = SchedaInizio(self)
        self._schede = [(self.inizio, "Inizio", "casa"), (self.verifica, "Verifica firme", "scudo"),
                        (self.estrazione, "Estrazione", "pacco"), (self.impostazioni, "Impostazioni", "ingranaggio")]
        for w, t, ic in self._schede:
            self.tabs.addTab(w, icona(ic, C["accento_chiaro"], 16), t)
        BUS.tema.connect(self._icone_schede)
        lay.addWidget(self.tabs, 1)

        self.lbl_info = etichetta("", "versione")
        self.statusBar().addPermanentWidget(self.lbl_info)
        self.verifica.richiesta_estrazione.connect(self._estrai_da_verifica)
        for p in (self.verifica, self.estrazione):
            p.messaggio.connect(lambda m: self.statusBar().showMessage(m, 5000))
        self.impostazioni.cambiate.connect(self.aggiorna_info)
        BUS.tsl.connect(self.aggiorna_info)
        self.overlay = OverlayRilascio(centro)
        self.aggiorna_info()
        scarica_tsl_in_sottofondo()
        if percorsi_avvio:
            QTimer.singleShot(300, lambda: self.gestisci_percorsi(percorsi_avvio))

    def _icone_schede(self):
        for i, (_w, _t, ic) in enumerate(self._schede):
            self.tabs.setTabIcon(i, icona(ic, C["accento_chiaro"], 16))

    def vai(self, w):
        self.tabs.setCurrentWidget(w)

    def aggiorna_info(self):
        self.lbl_info.setText(f"{len(ARCHIVIO.radici)} radici  ·  {ARCHIVIO.tsl_descrizione or 'Trusted List AgID non disponibile'}  ·  "
                              f"revoca {'attiva' if IMP['revoca'] else 'disattivata'}")

    def alterna_tema(self):
        IMP["tema"] = "Light" if C["sfondo"] == C_SCURO["sfondo"] else "Dark"
        IMP.salva()
        applica_tema()
        inv = {v: k for k, v in SchedaImpostazioni.TEMI.items()}
        self.impostazioni.tema.blockSignals(True)
        self.impostazioni.tema.setCurrentText(inv[IMP["tema"]])
        self.impostazioni.tema.blockSignals(False)

    def scegli_file_inizio(self):
        percorsi, _ = QFileDialog.getOpenFileNames(self, "Scegli i documenti", IMP["ultima_cartella"] or "",
                                                   "Documenti firmati (*.p7m *.p7s *.pdf *.xml *.p7m*);;Tutti i file (*)")
        if percorsi:
            IMP["ultima_cartella"] = os.path.dirname(percorsi[0])
            IMP.salva()
            self.gestisci_percorsi(percorsi)

    def scegli_cartella_inizio(self):
        c = QFileDialog.getExistingDirectory(self, "Scegli una cartella", IMP["ultima_cartella"] or "")
        if c:
            IMP["ultima_cartella"] = c
            IMP.salva()
            self.gestisci_percorsi([c])

    def _estrai_da_verifica(self, percorsi):
        self.vai(self.estrazione)
        self.estrazione.carica(percorsi, [], False)

    def gestisci_percorsi(self, elementi):
        files = [os.path.normpath(f) for f in elementi if os.path.isfile(f)]
        cartelle = [os.path.normpath(d) for d in elementi if os.path.isdir(d)]
        if not files and not cartelle:
            return
        corrente = self.tabs.currentWidget()
        if corrente in (self.verifica, self.estrazione):
            bersaglio, ricorsiva = corrente, bool(IMP["sottocartelle"])
        else:
            d = DialogoAzione(self, len(files), bool(cartelle))
            if d.exec() != QDialog.DialogCode.Accepted or not d.azione:
                return
            bersaglio = self.verifica if d.azione == "verifica" else self.estrazione
            ricorsiva = d.sotto.isChecked()
        self.vai(bersaglio)
        bersaglio.carica([f for f in files if supportato(os.path.basename(f), bersaglio._estensioni)], cartelle, ricorsiva)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.overlay.setGeometry(self.centralWidget().rect())

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            corrente = self.tabs.currentWidget()
            self.overlay.testo = {self.verifica: "Rilascia per verificare", self.estrazione: "Rilascia per estrarre"}.get(corrente, "Rilascia qui i documenti")
            self.overlay.setGeometry(self.centralWidget().rect())
            self.overlay.raise_()
            self.overlay.show()

    def dragLeaveEvent(self, _e):
        self.overlay.hide()

    def dropEvent(self, e):
        self.overlay.hide()
        percorsi = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        e.acceptProposedAction()
        if percorsi:
            QTimer.singleShot(0, lambda: self.gestisci_percorsi(percorsi))

    def closeEvent(self, e):
        for p in (self.verifica, self.estrazione):
            p.salva_colonne()
            p.ferma_e_attendi()
        IMP.salva()
        super().closeEvent(e)


def _eccezione_ui(tipo, valore, tb):
    testo = "".join(traceback.format_exception(tipo, valore, tb))
    log_errore(testo)
    sys.__stderr__ and sys.__stderr__.write(testo)
    try:
        avviso(QApplication.activeWindow(), "Errore imprevisto", f"{tipo.__name__}: {valore}\n\nDettagli salvati in errori.log", "error")
    except Exception:
        pass


def main():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("P7MReader.3")
        except Exception:
            pass
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setWindowIcon(icona_app())
    sys.excepthook = _eccezione_ui
    applica_tema()
    try:
        app.styleHints().colorSchemeChanged.connect(lambda _s: IMP["tema"] == "System" and applica_tema())
    except Exception:
        pass
    finestra = Finestra([a for a in sys.argv[1:] if os.path.exists(a)])
    finestra.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
