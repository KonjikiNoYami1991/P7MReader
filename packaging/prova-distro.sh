#!/usr/bin/env bash
# ============================================================
#  Prova P7MReader su una distribuzione Linux, con gli stessi pacchetti indicati nel README
#  ("Distribuzione per distribuzione"). Gira come root dentro un container della distribuzione.
#
#  Uso:  prova-distro.sh <cartella-sorgente> [cartella-pacchetti]
#    cartella-sorgente   checkout di P7MReader (anche in sola lettura: viene copiato)
#    cartella-pacchetti  contiene P7MReader-*-linux-x86_64.tar.gz e P7MReader-*-x86_64.AppImage
#                        (facoltativa: senza, si prova solo l'avvio da sorgente)
#
#  In locale, per esempio:
#    docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
#      -v "$PWD":/src:ro -v "$PWD/dist":/pacchetti:ro fedora:latest bash /src/packaging/prova-distro.sh /src /pacchetti
#
#  Se cambi un comando qui, cambialo anche nel README (italiano e inglese), e viceversa.
# ============================================================
set -uo pipefail

SRC="${1:?cartella sorgente}"
PAC="${2:-}"
LAVORO="$(mktemp -d)"
ERRORI=0
export QT_QPA_PLATFORM=offscreen
export HOME="$LAVORO/home" && mkdir -p "$HOME"

titolo() { printf '\n==== %s ====\n' "$*"; }
ok()     { printf '[OK] %s\n' "$*"; }
ko()     { printf '[ERRORE] %s\n' "$*"; ERRORI=$((ERRORI + 1)); }

. /etc/os-release
VER="${VERSION_ID:-rolling}"
MAGG="${VER%%.*}"
titolo "$PRETTY_NAME"

# ---------- Comandi della distribuzione (gli stessi del README, senza sudo) ----------
# BASE: solo per il container minimale (su un desktop ci sono gia'): non va nel README.
PY=python3
PACCHETTI=si   # si | no (glibc troppo vecchia: ci si aspetta l'errore GLIBC)
UV=no          # si = Python di sistema troppo vecchio, si usa uv
case "$ID" in
  debian|ubuntu|linuxmint)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    INST="apt-get install -y -qq"
    BASE="ca-certificates curl tar gzip libfontconfig1 libdbus-1-3 libglib2.0-0"
    FUSE="fuse3"
    GRAFICA="libegl1 libgl1 libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-shape0 libxcb-xkb1"
    SORGENTE="python3-venv git"
    { [ "$ID" = debian ] && [ "$MAGG" -lt 13 ]; } && UV=si
    { [ "$ID" = ubuntu ] && [ "$MAGG" -lt 24 ]; } && UV=si
    ;;
  fedora)
    INST="dnf install -y -q"
    BASE="curl tar gzip fontconfig dbus-libs glib2 findutils"
    FUSE="fuse3"
    GRAFICA="mesa-libEGL mesa-libGL libxcb libxkbcommon-x11 xcb-util-cursor xcb-util-wm xcb-util-image xcb-util-keysyms xcb-util-renderutil"
    SORGENTE="python3 git"
    ;;
  rhel|almalinux|rocky|centos)
    INST="dnf install -y -q"
    BASE="tar gzip fontconfig dbus-libs glib2 findutils"
    FUSE="fuse3"
    GRAFICA="mesa-libEGL mesa-libGL libxcb libxkbcommon-x11 xcb-util-cursor xcb-util-wm xcb-util-image xcb-util-keysyms xcb-util-renderutil"
    SORGENTE="python3 git"
    if [ "$MAGG" -lt 10 ]; then
        PACCHETTI=no
        PY=python3.12
        SORGENTE="python3.12 git"
    fi
    # README: se xcb-util-cursor non si trova, attivare EPEL
    $INST $GRAFICA >/dev/null 2>&1 || { echo "xcb-util-cursor & c. non trovati: attivo EPEL"; $INST epel-release; }
    ;;
  arch|manjaro|endeavouros|cachyos)
    pacman -Syu --noconfirm --needed archlinux-keyring >/dev/null
    INST="pacman -S --noconfirm --needed"
    BASE="curl tar gzip fontconfig dbus glib2"
    FUSE="fuse3"
    GRAFICA="libglvnd libxcb libxkbcommon-x11 xcb-util-cursor xcb-util-wm xcb-util-image xcb-util-keysyms xcb-util-renderutil"
    SORGENTE="python git"
    ;;
  opensuse-tumbleweed|opensuse-leap|opensuse-slowroll)
    INST="zypper -n -q install"
    BASE="curl tar gzip fontconfig libdbus-1-3 libglib-2_0-0 libgthread-2_0-0 findutils"
    FUSE="fuse3"
    GRAFICA="libglvnd libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-shape0 libxcb-xkb1"
    SORGENTE="python3 python3-pip git"
    if [ "$ID" = opensuse-leap ] && [ "$MAGG" -lt 16 ]; then
        PY=python3.12
        SORGENTE="python312 python312-pip git"
    fi
    ;;
  *) echo "Distribuzione non prevista: $ID"; exit 2 ;;
esac

titolo "Pacchetti di sistema"
echo "+ $INST $BASE" && $INST $BASE                   || ko "pacchetti di base"
echo "+ $INST $FUSE" && $INST $FUSE                   || ko "FUSE ($FUSE)"
echo "+ $INST $GRAFICA" && $INST $GRAFICA             || ko "librerie grafiche"
echo "+ $INST $SORGENTE" && $INST $SORGENTE           || ko "pacchetti per il sorgente"

# Nessuna libreria richiesta dal plugin Qt per X11 deve mancare
controlla_xcb() {
    local plugin="$1" mancanti
    mancanti="$(ldd "$plugin" 2>&1 | grep 'not found' || true)"
    if [ -z "$mancanti" ]; then ok "plugin xcb di Qt: nessuna libreria mancante ($2)"
    else ko "plugin xcb di Qt ($2), librerie mancanti:"; echo "$mancanti"; fi
}

# ---------- Pacchetti precompilati ----------
if [ -n "$PAC" ]; then
    TGZ="$(ls "$PAC"/P7MReader-*-linux-x86_64.tar.gz 2>/dev/null | head -1)"
    APPIMG="$(ls "$PAC"/P7MReader-*-x86_64.AppImage 2>/dev/null | head -1)"

    titolo "tar.gz"
    tar -xzf "$TGZ" -C "$LAVORO"
    BIN="$(ls -d "$LAVORO"/P7MReader-*-linux-x86_64)/P7MReader/P7MReader"
    if [ "$PACCHETTI" = si ]; then
        controlla_xcb "$(dirname "$BIN")/_internal/PyQt6/Qt6/plugins/platforms/libqxcb.so" "tar.gz"
        timeout 300 "$BIN" --selftest && ok "selftest del tar.gz" || ko "selftest del tar.gz"
        bash "$(dirname "$(dirname "$BIN")")/installa-linux.sh" && [ -x "$HOME/.local/bin/p7mreader" ] \
            && ok "installa-linux.sh" || ko "installa-linux.sh"
    else
        USCITA="$("$BIN" --selftest 2>&1)"
        if echo "$USCITA" | grep -q "GLIBC_2"; then ok "come atteso, non parte per la glibc: $(echo "$USCITA" | grep -o "GLIBC_2[.0-9]*' not found" | head -1)"
        else ko "doveva fallire per la glibc, invece: $USCITA"; fi
    fi

    titolo "AppImage"
    cp "$APPIMG" "$LAVORO/P7MReader.AppImage" && chmod +x "$LAVORO/P7MReader.AppImage"
    FM="$(for d in ${PATH//:/ }; do ls "$d"/fusermount* 2>/dev/null; done | head -1)"
    if [ -n "$FM" ] && [ -u "$FM" ]; then ok "il pacchetto $FUSE fornisce $FM (setuid root)"
    else ko "nessun fusermount setuid nel PATH dopo aver installato $FUSE"; fi
    if [ "$PACCHETTI" = si ]; then
        if [ -r /dev/fuse ] && [ -w /dev/fuse ]; then
            timeout 300 "$LAVORO/P7MReader.AppImage" --selftest && ok "selftest dell'AppImage (montata con FUSE)" \
                || ko "selftest dell'AppImage (montata con FUSE)"
        else
            echo "(/dev/fuse non disponibile nel container: provo senza FUSE)"
            timeout 300 "$LAVORO/P7MReader.AppImage" --appimage-extract-and-run --selftest \
                && ok "selftest dell'AppImage (--appimage-extract-and-run)" || ko "selftest dell'AppImage"
        fi
    fi
fi

# ---------- Avvio da sorgente (come nel README) ----------
titolo "Avvio da sorgente ($( [ "$UV" = si ] && echo "uv" || echo "$PY -m venv"))"
cp -a "$SRC" "$LAVORO/P7MReader" && rm -rf "$LAVORO/P7MReader/.venv" "$LAVORO/P7MReader/.git"
cd "$LAVORO/P7MReader"
DIP="PyQt6 pyhanko pyhanko-certvalidator asn1crypto cryptography lxml certifi tzdata"
if [ "$UV" = si ]; then
    curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null && export PATH="$HOME/.local/bin:$PATH"
    uv venv --python 3.13 .venv && uv pip install --python .venv -q $DIP || ko "uv venv / pip install"
else
    "$PY" --version
    "$PY" -m venv .venv && .venv/bin/pip install -q --disable-pip-version-check $DIP || ko "venv / pip install"
fi
PLUGIN="$(find .venv -name libqxcb.so | head -1)"
[ -n "$PLUGIN" ] && controlla_xcb "$PLUGIN" "sorgente" || ko "PyQt6 non installato"
timeout 300 .venv/bin/python P7MReader.py --selftest && ok "selftest da sorgente" || ko "selftest da sorgente"

titolo "Risultato: $PRETTY_NAME"
if [ "$ERRORI" -eq 0 ]; then echo "Tutto a posto."; else echo "$ERRORI errori."; fi
exit "$ERRORI"
