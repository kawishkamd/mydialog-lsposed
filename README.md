# MyDialog anti-tamper bypass

Bypasses the root / tamper gate and the Play Integrity gate of **MyDialog**
(`net.omobio.dialogsc`), a React Native app, so it runs normally on a rooted
device.

It ships as an **LSPosed module** (`lsposed-module/`), which needs Magisk +
LSPosed and nothing else - no PC, no `frida-server`, no terminal. The hooks arm
on the device whenever the app is opened and stay armed until you disable the
module.

Ground truth below is from **MyDialog 18.6.5** (`classes5.dex`).

## The two gates

Both gates end the same way: show a `Toast` and call `finish()`.

1. **Root / tamper** - `MainActivity.Z1()` on `onCreate`, re-run as
   `MainActivity.a2(boolean)` on every `onResume`. It ORs together ~13 probes.
2. **Integrity** - `MainActivity.z1()` → `T1()` asks Play Integrity for a
   token, `b2()` POSTs it to
   `https://selfcare.dialog.lk/scapp_6_0_1/index.php?r=/scapp/devices/verifyIntegrityToken`
   and acts on `{"success": …}`.

```
Z1() / a2()                        z1() -> T1() -> R1() -> Q1() -> b2()
   |  N1 J1 E1 L1 Utils.e                (Play Integrity token)      |
   |  D1 F1 M1 G1 I1                                                 |
   +-----------------------> A1(int) / B1(int, bool) <---------------+
                                    |
                              Toast + finish()
```

### Verified probe map (18.6.5)

| method | what it actually does |
|---|---|
| `b2(String,String)` | **is the POST** to `verifyIntegrityToken`; returns JSON `success` |
| `A1(int)` / `B1(int,boolean)` | the single kill funnel: `Toast` + `finish()` |
| `D1()` | `Settings.Secure.getInt(cr, "adb_enabled", 0) == 1` |
| `F1()` | `Settings.Secure.getInt(cr, "development_settings_enabled", 0) != 0` |
| `M1()` | `File.exists()` over 8 `su` paths |
| `I1()` | Magisk: 9 paths + 3 packages + `/proc/self/maps` |
| `G1()` | Frida: file paths + `/proc/self/maps` + `x1()` + `y1()` + `H1()` |
| `x1()` | `File("/").listFiles()` names containing `frida`/`linjector` |
| `y1()` | `Socket.connect(127.0.0.1, 27042..27046)` |
| `H1()` | `Runtime.exec("ps")` output scan |
| `E1()` | `FindDebugger` - `/proc/net/tcp`, `TracerPid` |
| `N1()` / `L1()` / `J1()` | `FindTaint` / `FindEmulator` / `FindMonkey` (`isUserAMonkey()`) |
| `w1()`, `O1()`, `K1()` | present but **never called** by the gates in 18.6.5 |
| `Utils.e(Context)` → `RootInfoCallable.call()` | RootBeer |

Two notes that matter for future maintenance:

- The `net.omobio.dialogsc.security.*` package (`SecurityValidator`,
  `SecurityManager`, `SecurityManagerAdvance`) is **dead code** in 18.6.5.
  `SecurityManagerAdvance`'s methods are `native` behind `libsecurity.so`,
  which is **not shipped** - the class cannot even initialise. The module hooks
  it defensively anyway.
- `CustomCertificatePinner` (the class holding the `sha256/…` pins) is **never
  instantiated**, and the network-security-config pin-set expired
  `2025-12-31`. That does **not** mean pinning is off: the autolinked
  `react-native-ssl-pinning` module (`RNSslPinning` is in the RN host's package
  list) builds an OkHttp `CertificatePinner` at runtime.
- **Pinning is ACTIVE and enforced on `selfcare.dialog.lk`** - confirmed on
  device (v18.6.5). Two pins are registered at runtime:

  ```
  sha256/kHLEkwjzfZp6X3HBjdFJEzlrBUhRA7wXNVi4gnYaqgc=   # leaf   SPKI, CN=dialog.lk
  sha256/Wec45nQiFwKvHtuHxSAMGkt19k+uPSw9JlEkxhvYPHk=   # intermediate SPKI, DigiCert Global G2
  ```

  Both match the live certificate chain (leaf + intermediate), so they are
  current, not stale. okhttp enforces them through the Kotlin-mangled
  `CertificatePinner.check$okhttp(String, Function0)` entry point - **not** the
  public `check(String, List)` overload, which is why hooking `check` alone
  shows nothing. Consequence: **MITM with a user-installed CA is blocked** on
  the API host; use passive capture, or bypass the pin at the okhttp layer.

  Where the pins come from: the call stack is
  `RNSslPinningModule.fetch` → `com.toyberman.Utils.OkHttpUtils.i` →
  `CertificatePinner$Builder.add`, i.e. the JS bundle supplies them. They are
  **not** literals in the bundle (not in the Hermes string table in any
  encoding), not in any dex, not the `res/8G.xml` pin-set (which holds three
  *different*, expired hashes), and not cached on disk. So the pin set is
  obtained at runtime and is **server-controlled - it can rotate without an
  app update.**

## How the LSPosed module works

Four tiers, in order of stability:

1. **Integrity** - `b2` → `true`. Because `b2` *is* the network call, this both
   neutralises the verdict and stops the real (failing) Play Integrity token
   from leaving the device. `P1(boolean)` (the verdict consumer) is a second,
   independent hook point if `b2` is renamed.
2. **Kill path** - `A1` / `B1` are the funnel every probe feeds into, so
   hooking them keeps the app alive regardless of which probe names change. If
   both fail to bind, a guarded `Activity.finish()` fallback is armed (it only
   suppresses `finish()` when the call stack contains `MainActivity`).
3. **Checks** - the individual probes, best-effort. Their obfuscated names
   churn every release.
4. **Framework** - `Settings.Secure.getInt` (`adb_enabled`,
  `development_settings_enabled`), `File.exists` (curated root/magisk/frida
   path list) and `ActivityManager.isUserAMonkey()`. These names never change,
   so this tier survives app updates on its own.

The module no longer fails silently: it logs the app version, every binding,
and shouts if a critical hook (integrity or kill-path) did not bind:

```
MyDialogBypass: loading net.omobio.dialogsc v18.6.5 (113010021) in net.omobio.dialogsc
MyDialogBypass:   bound   Settings.Secure.getInt(CR,String,int)
MyDialogBypass:   bound   File.exists()
MyDialogBypass:   bound   MainActivity.b2()
MyDialogBypass:   bound   MainActivity.A1()
...
MyDialogBypass: armed v18.6.5 (113010021): 31 bound, 0 skipped
MyDialogBypass: all critical hooks bound
```

## When MyDialog updates

R8 renames every app member on each release, so the `M_*` arrays go stale the
moment Dialog ships a new version. Nothing breaks silently: the module logs
`!!! CRITICAL hook(s) missing` when the integrity or kill-path tier fails to
bind.

Two facts make recovery mechanical:

- **string literals are never renamed**, and
- **`MainActivity` is the launcher activity**, declared in `AndroidManifest.xml`,
  so R8 keeps its name. The `MA` constant in `Module.java` rarely needs
  touching.

### Recovery procedure

```sh
# 1. pull the new build off the device (tap "update" first, or grab the APK)
adb shell su -c 'cp "$(pm path net.omobio.dialogsc | cut -d: -f2)" /sdcard/mydialog.apk'
adb pull /sdcard/mydialog.apk

# 2. rediscover the hook targets (decompiles only MainActivity)
lsposed-module/tools/find-gates.py --apk mydialog.apk

# 3. paste the printed M_* lines over the stale ones at the top of
#    lsposed-module/src/lk/mydialog/bypass/Module.java

# 4. rebuild, reinstall, and watch the module log
lsposed-module/build.sh
adb install -r lsposed-module/MyDialogBypass.apk
adb logcat -s MyDialogBypass
```

`find-gates.py` needs `jadx` on `PATH` (or `JADX=/path/to/jadx`) and a JRE
(auto-detected, or `JAVA_HOME=/path/to/jre`). It keys off
strings only a given gate contains (`verifyIntegrityToken`, `adb_enabled`,
`magisk`, `TracerPid`, `XposedBridge`, …) and attributes each hit to its
enclosing *named* method - so a `finish()` inside an anonymous `Runnable` is
still credited to the method that posted it. It also derives
`M_INTEGRITY_CONSUMER` and `M_MONITOR_KILL` structurally: they are simply the
methods that call the kill funnel (`A1`/`B1`). `--java MainActivity.java`
re-analyses an existing jadx dump without decompiling again.

Self-check: pointed at 18.6.5 it reproduces the arrays exactly
(`b2` / `A1` / `B1` / `U1,V1` / `P1` / `W1`).

Read the output, don't just paste it. A *rename* is mechanical, but a
*structural* change - the funnel stops calling `finish()`, the integrity POST
moves into native code, a new probe feeds a different kill path - makes the tool
print `!!` or propose a wrong-shaped method, and you have to work through
[The two gates](#the-two-gates) by hand.

### What survives an update with no edit

- **Tier 4 (framework)** - `Settings.Secure.getInt`, `File.exists`,
  `ActivityManager.isUserAMonkey`: Android names, not the app's.
- **The guard rails.** If the kill path fails to bind, the module arms a
  conditional `Activity.finish()` suppressor, so the app usually still starts
  long enough for you to fix the names.
- **The probe map above** stays a useful guide: `D1`/`F1` are still "the two
  `Settings.Secure.getInt` wrappers", whatever they get renamed to.

## Build

**The APK is not committed** (`*.apk` is ignored - binaries do not belong in git
history). Build it yourself: a clean clone compiles to a byte-identical
`classes.dex`.

You need an Android SDK `build-tools` directory, an `android.jar`, and the
Xposed API 82 jar. Nothing fetches them for you; get them once and point the
build at them. The defaults are where this repo's author keeps them:

| var | default | where to get it |
|---|---|---|
| `BUILD_TOOLS` | `~/.cache/mydialog/android/build-tools` | `sdkmanager "build-tools;34.0.0"` |
| `ANDROID_JAR` | `~/.cache/mydialog/android/android.jar` | `sdkmanager "platforms;android-30"`, then `platforms/android-30/android.jar` (API ≥ 30 is fine) |
| `XPOSED_API` | `~/.cache/mydialog/android/api-82.jar` | the `de.robv.android.xposed:api:82` artifact. Mirror: `https://maven.aliyun.com/repository/public/de/robv/android/xposed/api/82/api-82.jar` (sha256 `f48c635f1c7469fdec0e00ad2ea0b7a6b2f5b55065784a35b7ca3a84615e8e25`) |

```sh
BUILD_TOOLS=/path/to/build-tools \
ANDROID_JAR=/path/to/android.jar \
XPOSED_API=/path/to/api-82.jar \
JAVA=java ECJ_JAR=/path/to/ecj-3.36.0.jar \
lsposed-module/build.sh
```

With a JDK installed, drop `ECJ_JAR` and it uses `javac`. Either way `java`,
`keytool` and `zip` must be on `PATH` (the SDK's `aapt2`/`d8`/`apksigner` are
scripts that shell out to `java`). Output is `lsposed-module/MyDialogBypass.apk`
(minSdk 27, targetSdk 30).

### Signing - read this before installing

The first build creates `lsposed-module/.debug.keystore`, which is also ignored
(never commit a keystore, even a debug one). It is **not** in the repo, so:

- a fresh clone generates a **new signing key**, and
- Android refuses to update an installed app across a different key, so if you
  already installed a module built somewhere else, uninstall it first:
  `adb uninstall lk.mydialog.bypass`.

Keep `.debug.keystore` between builds - or copy it between machines, or set
`KEYSTORE=` - to keep one key.

### Install

Enable the module in LSPosed and scope it to `net.omobio.dialogsc`. Do not tick
"System Framework" - restarting the LSPosed daemon post-boot restarts zygote.

## Disclaimer

For use on devices you own, and for security research on the app you are
testing. Not affiliated with Dialog Axiata or Omobio.
