# MyDialog anti-tamper bypass

Bypasses the root / tamper gate and the Play Integrity gate of **MyDialog**
(`net.omobio.dialogsc`), a React Native app, so it runs normally on a rooted
device.

Two interchangeable routes:

| route | file | needs | notes |
|---|---|---|---|
| **LSPosed module** | `lsposed-module/` | Magisk + LSPosed, no PC | on-device, persistent, works with the PC disconnected |
| Frida script | `bypass.js` | a PC + `frida-server` | attach-only (spawn does not work on the test device) |

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
MyDialogBypass: loading net.omobio.dialogsc v18.6.5 (1865) in net.omobio.dialogsc
MyDialogBypass:   bound   Settings.Secure.getInt(CR,String,int)
MyDialogBypass:   bound   File.exists()
MyDialogBypass:   bound   MainActivity.b2()
MyDialogBypass:   bound   MainActivity.A1()
...
MyDialogBypass: armed v18.6.5 (1865): 31 bound, 0 skipped
MyDialogBypass: all critical hooks bound
```

After an app update, if you see

```
MyDialogBypass: !!! CRITICAL hook(s) missing on v18.7.0 (…)
```

add the new obfuscated names to the `M_*` lists at the top of
`lsposed-module/src/lk/mydialog/bypass/Module.java`.

## Build

The build no longer needs a full JDK - it can compile with the Eclipse compiler
on top of a bare JRE. It needs an Android `build-tools` directory, an
`android.jar` and the Xposed API 82 jar:

```sh
BUILD_TOOLS=/path/to/build-tools \
ANDROID_JAR=/path/to/android.jar \
XPOSED_API=/path/to/api-82.jar \
JAVA=java ECJ_JAR=/path/to/ecj-3.36.0.jar \
lsposed-module/build.sh
```

With a JDK installed, drop `ECJ_JAR` and it uses `javac`. Output is the signed
`lsposed-module/MyDialogBypass.apk` (minSdk 27, targetSdk 30). The signing key
lives in `lsposed-module/.debug.keystore` so it survives clean builds.

Install it, enable it in LSPosed, and scope it to `net.omobio.dialogsc`. Do not
tick "System Framework" - restarting the LSPosed daemon post-boot restarts
zygote.

## Frida route

```sh
pip install -r requirements.txt          # frida==16.7.19, pinned on purpose
adb push frida-server-16.7.19-android-arm64 /data/local/tmp/frida-server
adb shell "su -c '/data/local/tmp/frida-server &'"
frida -U -n MyDialog -l bypass.js
```

`bypass.js` is attach-only and installs the equivalent runtime hooks (still
using the 18.6.5 method names).

## Disclaimer

For use on devices you own, and for security research on the app you are
testing. Not affiliated with Dialog Axiata or Omobio.
