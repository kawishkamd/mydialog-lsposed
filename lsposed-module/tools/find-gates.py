#!/usr/bin/env python3
"""Re-discover the obfuscated hook targets in a new MyDialog build.

R8 renames every app member on each release, so the M_* arrays at the top of
Module.java go stale the moment Dialog ships a new version.  Two things survive
obfuscation and make recovery mechanical:

  * string literals are never renamed, and
  * MainActivity is the launcher activity, declared in AndroidManifest.xml, so
    R8 keeps its name (the MA constant in Module.java rarely needs touching).

So each gate is re-found by a string only that gate contains.

    tools/find-gates.py --apk /path/to/MyDialog.apk
    tools/find-gates.py --java /path/to/MainActivity.java   # existing dump

Output is print-ready for the M_* arrays in Module.java.  Suggestions for the
two critical arrays (integrity, kill path) are filtered by parameter shape, so
the tool cannot propose a method the module would fail to bind.

Note on the kill path: A1/B1 do not call Toast themselves -- they post the
message through a helper and then call finish().  So the funnel is found by
`finish()`, attributed to the enclosing NAMED method (anonymous Runnables are
hoisted into their parent), which is exactly the choke point we want.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

MA = "net.omobio.dialogsc.MainActivity"

# (label, regex that only that gate's body contains)
ANCHORS = [
    ("integrity POST", r"verifyIntegrityToken"),
    ("settings: adb", r'"adb_enabled"'),
    ("settings: dev-opts", r'"development_settings_enabled"'),
    ("su", r"/system/xbin/su|/system/bin/su|/sbin/su|/data/local/xbin/su|/data/local/su"),
    ("magisk", r"(?i)magisk"),
    ("frida", r"(?i)frida|27042|27043|27044|27045|27046"),
    ("debugger", r"FindDebugger|TracerPid|isDebuggerConnected"),
    ("monkey", r"isUserAMonkey|FindMonkey"),
    ("emulator", r"(?i)FindEmulator|goldfish|ranchu"),
    ("taint", r"FindTaint"),
    ("xposed", r"XposedBridge|de\.robv\.android\.xposed"),
]

FINISH = re.compile(r"\bfinish\(\)")       # the actual kill (bare or .finish())
TOAST = re.compile(r"Toast\.makeText")    # the message helper

MOD = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|abstract|native|synchronized|default)\s+)+"
    r"[\w$.<>\[\],\s]*?[\w$.<>\[\]]+\s+(\w+)\s*\(([^)]*)\)\s*(?:throws [\w.,\s]+)?\s*\{?\s*$"
)


def strip_comments(line):
    line = re.sub(r"/\*.*?\*/", " ", line)
    line = re.sub(r"//.*$", "", line)
    return line


def ptypes(params):
    """'final int i, boolean z' -> 'int,boolean'"""
    out = []
    for seg in params.split(","):
        toks = re.sub(r"\b(final|@\w+)\b", " ", seg.strip()).split()
        if not toks:
            continue
        out.append(toks[-2] if len(toks) >= 2 else toks[-1])   # type, not name
    return ",".join(out)


def find_jadx():
    for c in (os.environ.get("JADX"),
              os.path.expanduser("~/.cache/mydialog/jadx/bin/jadx"),
              "/tmp/opencode/tools/jadx/bin/jadx",
              shutil.which("jadx")):
        if c and os.path.exists(c):
            return c
    return None


def find_java_home():
    """jadx shells out to java; find a JRE even if it is not on PATH."""
    import glob
    if os.environ.get("JAVA_HOME"):
        jh = os.environ["JAVA_HOME"]
        for c in (os.path.join(jh, "bin", "java"), os.path.join(jh, "bin", "javac")):
            if os.path.exists(c):
                return jh
    pats = ["/tmp/opencode/tools/jdk*", "/tmp/opencode/tools/jre*",
            os.path.expanduser("~/.cache/mydialog/jdk*"),
            os.path.expanduser("~/.cache/mydialog/jre*"),
            "/usr/lib/jvm/*"]
    for pat in pats:
        for d in sorted(glob.glob(pat), reverse=True):
            if os.path.exists(os.path.join(d, "bin", "java")):
                return d
            for sub in glob.glob(os.path.join(d, "*", "bin", "java")):
                return os.path.dirname(os.path.dirname(sub))
    return None


def decompile(apk):
    jadx = find_jadx()
    if not jadx:
        sys.exit("jadx not found; set JADX=/path/to/jadx")
    out = tempfile.mkdtemp(prefix="findgates.")
    cmd = [jadx, "--no-res", "--single-class", MA, "-d", out, apk]
    print("[*] %s" % " ".join(cmd), file=sys.stderr)
    env = dict(os.environ)
    if not shutil.which("java"):
        jh = find_java_home()
        if jh:
            env["JAVA_HOME"] = jh
            env["PATH"] = os.path.join(jh, "bin") + os.pathsep + env.get("PATH", "")
            print("[*] java from JAVA_HOME=%s" % jh, file=sys.stderr)
        else:
            sys.exit("no java on PATH and no JRE found; set JAVA_HOME")
    subprocess.run(cmd, check=False, env=env)
    for root, _, files in os.walk(out):
        for f in files:
            if f == "MainActivity.java":
                return os.path.join(root, f)
    sys.exit("jadx did not produce MainActivity.java")


def frames(lines):
    """Every method declaration with its true extent, via brace depth.

    Anonymous inner-class methods are included (they are real frames), but
    callers attribute an anchor to the *outermost* enclosing frame, so a
    finish() inside a Runnable is credited to the method that posted it.
    """
    out = []
    stack = []
    depth = 0
    for i, raw in enumerate(lines):
        line = strip_comments(raw)
        m = MOD.match(line)
        if m:
            stack.append({"name": m.group(1), "params": m.group(2).strip(),
                          "start": i, "open": depth})
        depth += line.count("{") - line.count("}")
        while stack and depth <= stack[-1]["open"]:
            f = stack.pop()
            f["end"] = i
            out.append(f)
    while stack:
        f = stack.pop()
        f["end"] = len(lines) - 1
        out.append(f)
    return out


def outermost(fs, line_no):
    best = None
    for f in fs:
        if f["start"] <= line_no <= f["end"]:
            if best is None or f["open"] < best["open"]:
                best = f
    return best


def top_level(fs):
    """Frames not nested inside another frame (drops anonymous Runnables)."""
    out = []
    for f in fs:
        if not any(g is not f and g["start"] < f["start"] and f["end"] <= g["end"] for g in fs):
            out.append(f)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk")
    ap.add_argument("--java")
    args = ap.parse_args()

    if args.java:
        path = args.java
    elif args.apk:
        path = decompile(args.apk)
    else:
        sys.exit(__doc__)

    print("[*] analysing %s" % path, file=sys.stderr)
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    fs = frames(lines)

    def collect(rx):
        found = {}
        for i, raw in enumerate(lines):
            if rx.search(raw):
                f = outermost(fs, i)
                if f:
                    key = (f["name"], f["params"])
                    found.setdefault(key, f["start"])
        return sorted(found.items(), key=lambda kv: kv[1])

    kills = collect(FINISH)
    toasts = collect(TOAST)
    hits = {label: collect(re.compile(rx)) for label, rx in ANCHORS}

    print("\n" + "=" * 72)
    print("KILL FUNNEL  (calls finish()) -- M_KILL1 / M_KILL2")
    print("=" * 72)
    if not kills:
        print("  !! none found -- inspect MainActivity by hand")
    for (name, params), ln in kills:
        pt = ptypes(params)
        tag = {"int": "M_KILL1", "int,boolean": "M_KILL2"}.get(pt, "? check by hand")
        print("  line %-5d %-12s(%-22s) params=%-12s -> %s"
              % (ln + 1, name, params, pt, tag))

    print("\n" + "=" * 72)
    print("TOAST HELPERS  (Toast.makeText) -- M_TOAST")
    print("=" * 72)
    for (name, params), ln in toasts:
        print("  line %-5d %-12s(%s)" % (ln + 1, name, params))

    print("\n" + "=" * 72)
    print("GATES BY STRING ANCHOR")
    print("=" * 72)
    for label, _ in ANCHORS:
        got = hits[label]
        txt = ", ".join("%s(%s)" % (n, p) for (n, p), _ in got) if got else "-"
        print("  %-20s %s" % (label, txt))

    integ = [n for (n, _), _ in hits["integrity POST"]]
    k1 = [n for (n, p), _ in kills if ptypes(p) == "int"]
    k2 = [n for (n, p), _ in kills if ptypes(p) == "int,boolean"]
    tst = [n for (n, p), _ in toasts if ptypes(p) == "int"]

    # ---- everything that calls the funnel ---------------------------------
    # P1(boolean) consumes the integrity verdict; W1(void) is the monitor kill.
    # Found structurally: they are simply methods that call A1/B1.
    funnel = sorted(set(k1 + k2))
    kcall = re.compile(r"\b(?:%s)\s*\(" % "|".join(map(re.escape, funnel))) if funnel else None
    consumers, monitors = [], []
    if kcall:
        seen = set()
        for f in top_level(fs):
            if f["name"] in funnel or f["name"] in seen:
                continue
            body = "\n".join(lines[f["start"]:f["end"] + 1])
            if not kcall.search(body):
                continue
            ct = ptypes(f["params"])
            loops = re.search(r"\bwhile\s*\(|\bfor\s*\(|Thread\.sleep", body)
            if ct == "boolean":
                consumers.append((f["name"], f["start"]))
                seen.add(f["name"])
            elif ct == "" and not loops:
                monitors.append((f["name"], f["start"]))
                seen.add(f["name"])

    print("\n" + "=" * 72)
    print("SUGGESTED EDITS for Module.java")
    print("=" * 72)
    if integ:
        print('  M_INTEGRITY = {%s};' % ", ".join('"%s"' % n for n in integ))
    else:
        print("  M_INTEGRITY = {};   /* !! NOT FOUND -- inspect by hand */")
    print(('  M_INTEGRITY_CONSUMER = {%s};' % ", ".join('"%s"' % n for n, _ in consumers))
          if consumers else "  M_INTEGRITY_CONSUMER = {};   /* !! none -- inspect by hand */")
    print(('  M_KILL1     = {%s};' % ", ".join('"%s"' % n for n in k1)) if k1
          else "  M_KILL1     = {};   /* !! NOT FOUND */")
    print(('  M_KILL2     = {%s};' % ", ".join('"%s"' % n for n in k2)) if k2
          else "  M_KILL2     = {};   /* !! NOT FOUND */")
    if tst:
        print('  M_TOAST     = {%s};' % ", ".join('"%s"' % n for n in tst))
    print(('  M_MONITOR_KILL = {%s};' % ", ".join('"%s"' % n for n, _ in monitors))
          if monitors else "  M_MONITOR_KILL = {};   /* !! none -- inspect by hand */")

    checks, skip = [], set(integ) | set(funnel) | set(tst) | {n for n, _ in consumers} | {n for n, _ in monitors}
    for label, _ in ANCHORS:
        for (n, _), _ in hits[label]:
            if n not in checks and n not in skip:
                checks.append(n)
    if checks:
        print('  M_CHECKS    = {%s};' % ", ".join('"%s"' % n for n in checks))
    print("\n  After install the module MUST log 'all critical hooks bound'.")

    if consumers or monitors:
        print("\n  (by-structure candidates, confirm against your notes:)")
        for n, ln in consumers:
            print("    consumer  %-12s line %d" % (n, ln + 1))
        for n, ln in monitors:
            print("    monitor   %-12s line %d" % (n, ln + 1))


if __name__ == "__main__":
    main()
