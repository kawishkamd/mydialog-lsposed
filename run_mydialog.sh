#!/usr/bin/env bash
#
# MyDialog (Dialog Self Care) on a rooted device -- integrity/root gate bypass.
#
# Usage:  ./run_mydialog.sh
#
# Requirements:
#   * adb in PATH, device connected
#   * root active (Magisk). NOTE: on this device root only exists when booted
#     via recovery -- `adb reboot recovery`, or Vol-Up + Power.
#   * internet on the first run (to fetch frida-server / the frida python pkg)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="net.omobio.dialogsc"
FRIDA_VER="16.7.19"
DEV_SERVER="/data/local/tmp/frida-server16"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/mydialog"
VENV="$HERE/.venv"

say() { printf '\n%s\n' "$*"; }

# ---- adb / device -----------------------------------------------------------
command -v adb >/dev/null 2>&1 || { echo "adb is not in PATH"; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "no device (check 'adb devices')"; exit 1; }

# ---- root -------------------------------------------------------------------
if ! adb shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
    say "No root."
    say "This device only has root when booted through recovery. Run:"
    say "    adb reboot recovery        (or hold Vol-Up + Power)"
    say "then unlock the screen and run this script again."
    exit 1
fi

if ! adb shell "pm path $PKG" >/dev/null 2>&1; then
    echo "MyDialog ($PKG) is not installed on the device."
    exit 1
fi

# ---- frida-server on the device --------------------------------------------
if ! adb shell "test -f $DEV_SERVER" 2>/dev/null; then
    say "Installing frida-server $FRIDA_VER on the device (one time) ..."
    mkdir -p "$CACHE"
    if [ ! -f "$CACHE/frida-server-android-arm64" ]; then
        curl -fSL --retry 3 \
            "https://github.com/frida/frida/releases/download/$FRIDA_VER/frida-server-$FRIDA_VER-android-arm64.xz" \
            -o "$CACHE/fs.xz"
        xz -d -f "$CACHE/fs.xz"
        mv "$CACHE/fs" "$CACHE/frida-server-android-arm64"
    fi
    adb push "$CACHE/frida-server-android-arm64" "$DEV_SERVER" >/dev/null
    adb shell "su -c 'chmod 755 $DEV_SERVER'"
fi

if ! adb shell 'ps -A' 2>/dev/null | grep -q 'frida-server'; then
    say "Starting frida-server ..."
    adb shell "su -c 'setsid $DEV_SERVER >/dev/null 2>&1 </dev/null &'"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1
        adb shell 'ps -A' 2>/dev/null | grep -q 'frida-server' && break
    done
    adb shell 'ps -A' 2>/dev/null | grep -q 'frida-server' \
        || { echo "frida-server failed to start"; exit 1; }
fi

# ---- python frida bindings (must match frida-server) ------------------------
if [ ! -x "$VENV/bin/python" ]; then
    say "Creating the python environment (one time) ..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q --upgrade pip
    "$VENV/bin/pip" install -q "frida==$FRIDA_VER"
fi

if ! "$VENV/bin/python" -c 'import frida' >/dev/null 2>&1; then
    say "Repairing the python environment ..."
    "$VENV/bin/pip" install -q "frida==$FRIDA_VER"
fi

# ---- go ---------------------------------------------------------------------
say "Launching MyDialog with the security gates bypassed."
say "Keep this terminal open the whole time you use the app."
exec "$VENV/bin/python" "$HERE/run_bypass.py" "${1:-86400}"
