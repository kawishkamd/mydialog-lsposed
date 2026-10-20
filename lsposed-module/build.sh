#!/usr/bin/env bash
#
# Builds MyDialogBypass.apk (an LSPosed/Xposed module) without Android Studio.
#
# Needs a Java compiler plus an Android SDK "build-tools" dir, an android.jar
# and the Xposed API 82 jar.  Set them via env vars if they are not in the
# default location (which is where the helper in this repo puts them):
#
#   BUILD_TOOLS   e.g. ~/.cache/mydialog/android/build-tools
#   ANDROID_JAR   e.g. ~/.cache/mydialog/android/android.jar
#   XPOSED_API    e.g. ~/.cache/mydialog/android/api-82.jar
#
# Compiler: uses "javac" from a JDK by default.  If you only have a JRE, point
# ECJ_JAR at the Eclipse compiler instead (no JDK needed):
#
#   JAVA=java ECJ_JAR=/path/to/ecj-3.36.0.jar ./build.sh
#
# (keytool is only needed the first time, to create the debug keystore.)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/mydialog/android"

BUILD_TOOLS="${BUILD_TOOLS:-$CACHE/build-tools}"
ANDROID_JAR="${ANDROID_JAR:-$CACHE/android.jar}"
XPOSED_API="${XPOSED_API:-$CACHE/api-82.jar}"
JAVA="${JAVA:-java}"
JAVAC="${JAVAC:-javac}"
ECJ_JAR="${ECJ_JAR:-}"

AAPT2="$BUILD_TOOLS/aapt2"
D8="$BUILD_TOOLS/d8"
ZIPALIGN="$BUILD_TOOLS/zipalign"
APKSIGNER="$BUILD_TOOLS/apksigner"

for f in "$AAPT2" "$D8" "$ZIPALIGN" "$APKSIGNER" "$ANDROID_JAR" "$XPOSED_API"; do
    [ -e "$f" ] || { echo "missing: $f"; exit 1; }
done

OUT="$HERE/build"
rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/dex" "$OUT/res"

echo "== 1/7 resources"
"$AAPT2" compile --dir "$HERE/res" -o "$OUT/res.zip"

echo "== 2/7 compile java"
SRC=$(find "$HERE/src" -name '*.java')
if [ -n "$ECJ_JAR" ]; then
    "$JAVA" -jar "$ECJ_JAR" -nowarn -source 8 -target 8 \
        -cp "$ANDROID_JAR:$XPOSED_API" \
        -d "$OUT/classes" \
        $SRC
else
    "$JAVAC" -nowarn -source 8 -target 8 \
        -cp "$ANDROID_JAR:$XPOSED_API" \
        -d "$OUT/classes" \
        $SRC
fi

echo "== 3/7 dex"
"$D8" --lib "$ANDROID_JAR" --min-api 27 --output "$OUT/dex" \
    $(find "$OUT/classes" -name '*.class')

echo "== 4/7 link apk"
"$AAPT2" link \
    -o "$OUT/base.apk" \
    -I "$ANDROID_JAR" \
    --manifest "$HERE/AndroidManifest.xml" \
    --min-sdk-version 27 --target-sdk-version 30 \
    "$OUT/res.zip"

echo "== 5/7 add classes.dex + xposed_init"
cp "$OUT/dex/classes.dex" "$OUT/classes.dex"
(cd "$OUT" && zip -q base.apk classes.dex)
(cd "$HERE" && zip -q "$OUT/base.apk" assets/xposed_init)

echo "== 6/7 zipalign"
"$ZIPALIGN" -f 4 "$OUT/base.apk" "$OUT/aligned.apk"

echo "== 7/7 sign"
# Keystore lives outside $OUT so a clean build keeps the same signing key.
KS="${KEYSTORE:-$HERE/.debug.keystore}"
if [ ! -f "$KS" ]; then
    KEYTOOL="${KEYTOOL:-keytool}"
    command -v "$KEYTOOL" >/dev/null 2>&1 || {
        echo "no keystore at $KS and no keytool on PATH (set KEYTOOL or KEYSTORE)"; exit 1; }
    "$KEYTOOL" -genkeypair -keystore "$KS" -alias androiddebugkey \
        -storepass android -keypass android \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
fi
"$APKSIGNER" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --out "$HERE/MyDialogBypass.apk" "$OUT/aligned.apk"

echo
echo "built: $HERE/MyDialogBypass.apk"
"$AAPT2" dump badging "$HERE/MyDialogBypass.apk" 2>/dev/null | head -3 || true
