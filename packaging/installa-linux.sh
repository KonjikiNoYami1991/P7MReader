#!/usr/bin/env bash
# Installa P7MReader (versione in cartella) per l'utente corrente, senza permessi di amministratore:
#   programma in ~/.local/opt/p7mreader, comando "p7mreader" in ~/.local/bin, voce nel menu delle applicazioni.
# Uso:  ./installa-linux.sh            (installa/aggiorna)
#       ./installa-linux.sh --rimuovi  (disinstalla)
set -euo pipefail
QUI="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.local/opt/p7mreader"
BIN="$HOME/.local/bin"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONE="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/256x256/apps"

if [ "${1:-}" = "--rimuovi" ]; then
    rm -rf "$DEST" "$BIN/p7mreader" "$APPS/p7mreader.desktop" "$ICONE/p7mreader.png"
    command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" || true
    echo "P7MReader rimosso."
    exit 0
fi

mkdir -p "$DEST" "$BIN" "$APPS" "$ICONE"
rm -rf "${DEST:?}"/*
cp -a "$QUI/P7MReader/." "$DEST/"
ln -sf "$DEST/P7MReader" "$BIN/p7mreader"
cp "$QUI/p7mreader.png" "$ICONE/p7mreader.png"
sed "s|^Exec=.*|Exec=\"$DEST/P7MReader\" %F|" "$QUI/p7mreader.desktop" > "$APPS/p7mreader.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" || true
echo "P7MReader installato: lo trovi nel menu delle applicazioni o col comando 'p7mreader'."
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Nota: aggiungi $BIN al PATH per usare il comando da terminale.";; esac
