package lk.mydialog.bypass;

import android.content.ContentResolver;
import android.content.Context;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * MyDialog (net.omobio.dialogsc) root/tamper + integrity bypass.
 *
 * Ground truth is v18.6.5, refactored into four tiers so an app update cannot
 * silently brick the bypass again:
 *
 *   1. INTEGRITY  MainActivity.b2(String,String) *is* the POST to
 *                 /scapp/devices/verifyIntegrityToken -- replacing it makes the
 *                 client trust the verdict AND stops the (real, failing) Play
 *                 Integrity token from ever leaving the device. MainActivity.P1
 *                 (the verdict consumer) is a second, independent hook point.
 *
 *   2. KILL PATH  Z1()/a2() run every probe and then funnel into exactly one of
 *                 A1(int)/B1(int,boolean) -> toast + finish(). Hooking the
 *                 funnel keeps the app alive no matter which probe names change.
 *                 A guarded Activity.finish() fallback is armed only if BOTH
 *                 funnels fail to bind.
 *
 *   3. CHECKS     The individual probes. Their obfuscated names churn every
 *                 release; the M_* lists below are where new names get added.
 *
 *   4. FRAMEWORK  Settings.Secure.getInt / File.exists / isUserAMonkey. These
 *                 framework names are stable forever, so this tier survives app
 *                 updates on its own for the adb, dev-options, su/magisk/frida
 *                 file and monkey checks.
 *
 * Every hook is logged, and the module shouts if a critical hook did not bind,
 * so a version bump shows up as an obvious line in the LSPosed log instead of a
 * silent failure.
 */
public class Module implements IXposedHookLoadPackage {

    private static final String TAG = "MyDialogBypass: ";
    private static final String PKG = "net.omobio.dialogsc";
    private static final String MA  = "net.omobio.dialogsc.MainActivity";

    private static int bound;
    private static int skipped;
    private static boolean criticalMissing;

    /* ---- 1. integrity verdict ------------------------------------------- */
    /* b2(String token, String nonce) -> boolean : the POST itself            */
    private static final String[] M_INTEGRITY = {"b2"};
    /* P1(boolean ok) -> void : the verdict consumer (second hook point)      */
    private static final String[] M_INTEGRITY_CONSUMER = {"P1"};

    /* ---- 2. kill path (choke point) ------------------------------------- */
    private static final String[] M_KILL1 = {"A1"};             /* void(int)   */
    private static final String[] M_KILL2 = {"B1"};             /* void(int,boolean) */
    private static final String[] M_TOAST = {"U1", "V1"};       /* void(int)   */
    private static final String[] M_MONITOR_KILL = {"W1"};      /* void()      */

    /* ---- 3. individual root / tamper probes ----------------------------- */
    private static final String[] M_CHECKS = {
            "N1", "J1", "E1", "L1", "D1", "F1", "M1", "G1", "I1",
            "H1", "O1", "x1", "y1"
    };

    /* ---- 4. framework hardening (name-stable) --------------------------- */
    private static final Set<String> HIDE_SETTINGS = new HashSet<String>(Arrays.asList(
            "adb_enabled", "development_settings_enabled"));

    /* Exact paths the app probes for root / magisk / frida. Matching is exact
       (plus a couple of unambiguous substrings), so legitimate File.exists()
       calls elsewhere are untouched. */
    private static final String[] HIDE_PATHS = {
            /* su */
            "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su",
            "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su",
            "/data/local/su",
            /* magisk */
            "/sbin/.magisk/", "/data/adb/magisk/", "/data/adb/magisk.db",
            "/cache/.magisk/", "/system/bin/magisk", "/system/xbin/magisk",
            "/system/app/MagiskManager/", "/system/etc/init.d/magisk",
            "/data/adb/modules", "/data/adb/magisk_simple", "/sbin/.magisk/mirror",
            "/data/adb/service.d", "/data/adb/post-fs-data.d",
            /* hidden root files */
            "/system/bin/.ext", "/system/usr/we-need-root", "/system/xbin/busybox",
            "/cache/su", "/data/su", "/dev/su", "/system/app/Superuser.apk",
            "/system/etc/init.d/99SuperSUDaemon", "/system/recovery-from-boot.p",
            "/system/recovery-resource.dat",
            /* frida */
            "/data/local/tmp/frida-server", "/data/local/tmp/frida",
            "/system/bin/frida-server", "/system/xbin/frida-server",
            "/data/local/tmp/re.frida.server", "/sdcard/frida-server",
            "/data/local/tmp/linjector"
    };

    /* ===================================================================== */
    /*  hook plumbing                                                        */
    /* ===================================================================== */

    private static boolean bind(Class<?> cls, String name, Object value, Class<?>... params) {
        try {
            Object[] args = new Object[params.length + 1];
            System.arraycopy(params, 0, args, 0, params.length);
            args[params.length] = XC_MethodReplacement.returnConstant(value);
            XposedHelpers.findAndHookMethod(cls, name, args);
            bound++;
            XposedBridge.log(TAG + "  bound   " + cls.getSimpleName() + "." + name + "()");
            return true;
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  skipped " + cls.getSimpleName() + "." + name + "() ["
                    + t.getClass().getSimpleName() + "]");
            return false;
        }
    }

    private static boolean bindFirst(Class<?> cls, String[] names, Object value, Class<?>... params) {
        for (int i = 0; i < names.length; i++) {
            if (bind(cls, names[i], value, params)) {
                return true;
            }
        }
        return false;
    }

    private static void bindIfPresent(ClassLoader cl, String className, String name,
                                      Object value, Class<?>... params) {
        try {
            bind(XposedHelpers.findClass(className, cl), name, value, params);
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  absent  " + className + "." + name + "()");
        }
    }

    /* ===================================================================== */
    /*  4. framework tier -- stable across every app release                 */
    /* ===================================================================== */

    private static void hookSettingsSecure(ClassLoader cl) {
        XC_MethodHook hide = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam p) {
                try {
                    String key = (String) p.args[1];
                    if (key != null && HIDE_SETTINGS.contains(key)) {
                        p.setResult(0);
                    }
                } catch (Throwable ignored) {
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod("android.provider.Settings$Secure", cl,
                    "getInt", ContentResolver.class, String.class, hide);
            bound++;
            XposedBridge.log(TAG + "  bound   Settings.Secure.getInt(CR,String)");
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  skipped Settings.Secure.getInt(CR,String)");
        }
        try {
            XposedHelpers.findAndHookMethod("android.provider.Settings$Secure", cl,
                    "getInt", ContentResolver.class, String.class, int.class, hide);
            bound++;
            XposedBridge.log(TAG + "  bound   Settings.Secure.getInt(CR,String,int)");
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  skipped Settings.Secure.getInt(CR,String,int)");
        }
    }

    private static void hookFileExists() {
        try {
            XposedHelpers.findAndHookMethod(File.class, "exists", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        File f = (File) p.thisObject;
                        if (f != null && isHiddenPath(f.getPath())) {
                            p.setResult(Boolean.FALSE);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            bound++;
            XposedBridge.log(TAG + "  bound   File.exists()");
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  skipped File.exists()");
        }
    }

    private static void hookMonkey(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod("android.app.ActivityManager", cl,
                    "isUserAMonkey", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            p.setResult(Boolean.FALSE);
                        }
                    });
            bound++;
            XposedBridge.log(TAG + "  bound   ActivityManager.isUserAMonkey()");
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  skipped ActivityManager.isUserAMonkey()");
        }
    }

    private static boolean isHiddenPath(String path) {
        if (path == null) {
            return false;
        }
        for (int i = 0; i < HIDE_PATHS.length; i++) {
            if (path.equals(HIDE_PATHS[i])) {
                return true;
            }
        }
        return path.contains("frida") || path.contains("magisk") || path.endsWith("/su");
    }

    /* ===================================================================== */
    /*  2b. guarded finish() fallback (only armed if the funnels are gone)    */
    /* ===================================================================== */

    private static boolean armFinishFallback(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod("android.app.Activity", cl, "finish",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            if (calledFromMainActivity()) {
                                XposedBridge.log(TAG + "  suppressed MainActivity.finish()");
                                p.setResult(null);
                            }
                        }
                    });
            bound++;
            XposedBridge.log(TAG + "  bound   Activity.finish() [fallback]");
            return true;
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  skipped Activity.finish() [fallback]");
            return false;
        }
    }

    private static boolean calledFromMainActivity() {
        StackTraceElement[] st = new Throwable().getStackTrace();
        int n = st.length < 24 ? st.length : 24;
        for (int i = 0; i < n; i++) {
            if (MA.equals(st[i].getClassName())) {
                return true;
            }
        }
        return false;
    }

    /* ===================================================================== */
    /*  entry point                                                          */
    /* ===================================================================== */

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if (!PKG.equals(lp.packageName)) {
            return;
        }

        ClassLoader cl = lp.classLoader;
        String ver = version(cl, lp);
        XposedBridge.log(TAG + "loading " + PKG + " v" + ver + " in " + lp.processName);

        /* tier 4: framework hardening -- works even if MainActivity moves */
        hookSettingsSecure(cl);
        hookFileExists();
        hookMonkey(cl);

        Class<?> ma;
        try {
            ma = XposedHelpers.findClass(MA, cl);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "FATAL: " + MA + " not found: " + t);
            criticalMissing = true;
            summary(ver);
            return;
        }

        /* tier 1: integrity */
        boolean integPost = bindFirst(ma, M_INTEGRITY, Boolean.TRUE, String.class, String.class);
        boolean integConsumer = bindFirst(ma, M_INTEGRITY_CONSUMER, null, boolean.class);
        if (!integPost) {
            if (integConsumer) {
                XposedBridge.log(TAG + "  NOTE incomplete integrity: verdict is ignored, "
                        + "but the Play Integrity token is still POSTed (b2 renamed?)");
            } else {
                criticalMissing = true;
                XposedBridge.log(TAG + "  MISS integrity hooks " + Arrays.toString(M_INTEGRITY)
                        + " / " + Arrays.toString(M_INTEGRITY_CONSUMER));
            }
        }

        /* tier 2: kill path (primary) */
        boolean kill1 = bindFirst(ma, M_KILL1, null, int.class);
        boolean kill2 = bindFirst(ma, M_KILL2, null, int.class, boolean.class);
        if (!kill1 && !kill2) {
            criticalMissing = true;
            XposedBridge.log(TAG + "  MISS kill-path hooks " + Arrays.toString(M_KILL1)
                    + " / " + Arrays.toString(M_KILL2) + " -> arming finish() fallback");
            armFinishFallback(cl);
        }
        bindFirst(ma, M_TOAST, null, int.class);
        bindFirst(ma, M_MONITOR_KILL, null);

        /* tier 3: individual probes */
        for (int i = 0; i < M_CHECKS.length; i++) {
            bind(ma, M_CHECKS[i], Boolean.FALSE);
        }

        /* helpers used by the React Native bridge */
        bindIfPresent(cl, "net.omobio.dialogsc.Utils", "e", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.support.lib.RootInfoCallable", "call", Boolean.FALSE);

        /* legacy security package: dead in 18.6.5 (libsecurity.so is not even
           shipped, so SecurityManagerAdvance cannot initialise) -- kept
           defensively in case a future build wires it back up. */
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityValidator",
                "isSecure", Boolean.TRUE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "performComprehensiveSecurityCheck", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isProductionSecure", Boolean.TRUE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.SecurityManagerAdvance",
                "performSecurityCheck", Boolean.FALSE);
        bindIfPresent(cl, "net.omobio.dialogsc.SecurityManagerAdvance",
                "checkFridaLibs", Boolean.FALSE);
        bindIfPresent(cl, "net.omobio.dialogsc.SecurityManagerAdvance",
                "checkFridaPort", Boolean.FALSE);
        bindIfPresent(cl, "net.omobio.dialogsc.SecurityManagerAdvance",
                "checkFridaServer", Boolean.FALSE);

        summary(ver);
    }

    private static void summary(String ver) {
        XposedBridge.log(TAG + "armed v" + ver + ": " + bound + " bound, " + skipped + " skipped");
        if (criticalMissing) {
            XposedBridge.log(TAG + "!!! CRITICAL hook(s) missing on v" + ver
                    + " - the app may still self-terminate. Add the new method names to the "
                    + "M_* lists in Module.java !!!");
        } else {
            XposedBridge.log(TAG + "all critical hooks bound");
        }
    }

    /**
     * App version, for the log.
     *
     * LSPosed hands us a null appInfo, hidden-API reflection on ActivityThread is
     * blocked, and R8 renamed BuildConfig.VERSION_NAME -- so scan the app's own
     * BuildConfig for the static String that looks like a version.
     */
    private static String version(ClassLoader cl, XC_LoadPackage.LoadPackageParam lp) {
        try {
            Class<?> bc = XposedHelpers.findClass("net.omobio.dialogsc.BuildConfig", cl);
            Object vc = XposedHelpers.getStaticObjectField(bc, "VERSION_CODE");
            java.lang.reflect.Field[] fs = bc.getDeclaredFields();
            for (int i = 0; i < fs.length; i++) {
                java.lang.reflect.Field f = fs[i];
                if (f.getType() != String.class
                        || !java.lang.reflect.Modifier.isStatic(f.getModifiers())) {
                    continue;
                }
                f.setAccessible(true);
                Object v = f.get(null);
                if (v instanceof String && ((String) v).matches("\\d+\\.\\d+\\.\\d+.*")) {
                    return v + " (" + vc + ")";
                }
            }
            if (vc != null) {
                return "build " + vc;
            }
        } catch (Throwable ignored) {
        }
        try {
            Object ai = lp.appInfo;
            if (ai != null) {
                Object vn = XposedHelpers.getObjectField(ai, "versionName");
                if (vn != null) {
                    return String.valueOf(vn);
                }
            }
        } catch (Throwable ignored) {
        }
        return "?";
    }
}
