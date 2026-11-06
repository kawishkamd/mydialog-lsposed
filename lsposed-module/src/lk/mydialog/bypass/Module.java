package lk.mydialog.bypass;

import android.content.ContentResolver;
import android.content.Context;
import android.os.Looper;

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
 * Supports both v18.6.5 and v18.6.6+ (R8 synthetic Runnable refactor):
 *
 *   1. INTEGRITY  In 18.6.5: MainActivity.b2(String,String) POST.
 *                 In 18.6.6: a.Pq0 (case 5) requests Play Integrity token;
 *                 a.Ja (case 7) consumes verdict (forced to success=true).
 *
 *   2. KILL PATH  In 18.6.5: A1(int)/B1(int,boolean) funnels in MainActivity.
 *                 In 18.6.6: a.cs0 tamper thread and a.Yj toast runnable.
 *                 Universal Activity.finish() suppressor on MainActivity blocks
 *                 any security-originated kill.
 *
 *   3. CHECKS     Individual probes on MainActivity (l, m, n, o, p, q, r, s)
 *                 and external probe helpers (a.HV.r TracerPid, a.Nm1.a RootBeer).
 *
 *   4. FRAMEWORK  Settings.Secure.getInt / File.exists / isUserAMonkey.
 */
public class Module implements IXposedHookLoadPackage {

    private static final String TAG = "MyDialogBypass: ";
    private static final String PKG = "net.omobio.dialogsc";
    private static final String MA  = "net.omobio.dialogsc.MainActivity";

    private static int bound;
    private static int skipped;
    private static boolean criticalMissing;

    /* ---- 1. integrity verdict ------------------------------------------- */
    /* 18.6.5: b2(String token, String nonce) -> boolean : the POST itself    */
    private static final String[] M_INTEGRITY = {"b2"};
    /* 18.6.5: P1(boolean ok) -> void : the verdict consumer                  */
    private static final String[] M_INTEGRITY_CONSUMER = {"P1"};

    /* ---- 2. kill path (choke point) ------------------------------------- */
    /* 18.6.5 funnels                                                        */
    private static final String[] M_KILL1 = {"A1"};             /* void(int)   */
    private static final String[] M_KILL2 = {"B1"};             /* void(int,boolean) */
    private static final String[] M_TOAST = {"U1", "V1"};       /* void(int)   */
    private static final String[] M_MONITOR_KILL = {"W1"};      /* void()      */

    /* ---- 3. individual root / tamper probes ----------------------------- */
    /* 18.6.6+ probes on MainActivity with 0 params -> boolean               */
    private static final String[] M_CHECKS_1866_NOARG = {
            "n", "o", "p", "q", "r", "s"
    };

    /* 18.6.6+ probes on MainActivity taking MainActivity -> boolean         */
    private static final String[] M_CHECKS_1866_WITH_MA = {
            "l", "m"
    };

    /* 18.6.5 probes on MainActivity (no params -> boolean)                  */
    private static final String[] M_CHECKS_1865 = {
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
    /*  18.6.6+ synthetic runnable hooks                                     */
    /* ===================================================================== */

    private static boolean hookCs0(ClassLoader cl) {
        try {
            Class<?> cls = XposedHelpers.findClass("a.cs0", cl);
            XposedHelpers.findAndHookMethod(cls, "run", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        int a = XposedHelpers.getIntField(p.thisObject, "a");
                        if (a == 0 || a == 1) {
                            XposedBridge.log(TAG + "  suppressed a.cs0.run(case " + a + ") [root/tamper thread]");
                            p.setResult(null);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            bound++;
            XposedBridge.log(TAG + "  bound   a.cs0.run() [root/tamper runner]");
            return true;
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  absent  a.cs0.run()");
            return false;
        }
    }

    private static boolean hookPq0(ClassLoader cl) {
        try {
            Class<?> cls = XposedHelpers.findClass("a.Pq0", cl);
            XposedHelpers.findAndHookMethod(cls, "run", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        int a = XposedHelpers.getIntField(p.thisObject, "a");
                        if (a == 5) {
                            XposedBridge.log(TAG + "  suppressed a.Pq0.run(case 5) [Play Integrity requester]");
                            p.setResult(null);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            bound++;
            XposedBridge.log(TAG + "  bound   a.Pq0.run() [Play Integrity requester]");
            return true;
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  absent  a.Pq0.run()");
            return false;
        }
    }

    private static boolean hookJa(ClassLoader cl) {
        try {
            Class<?> cls = XposedHelpers.findClass("a.Ja", cl);
            XposedHelpers.findAndHookConstructor(cls, Object.class, boolean.class, int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        int type = (Integer) p.args[2];
                        if (type == 7 && p.args[0] != null && MA.equals(p.args[0].getClass().getName())) {
                            p.args[1] = Boolean.TRUE;
                            XposedBridge.log(TAG + "  forced a.Ja integrity verdict success=true");
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            bound++;
            XposedBridge.log(TAG + "  bound   a.Ja.<init>() [integrity verdict consumer]");
            return true;
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  absent  a.Ja.<init>()");
            return false;
        }
    }

    private static boolean hookYj(ClassLoader cl) {
        try {
            Class<?> cls = XposedHelpers.findClass("a.Yj", cl);
            XposedHelpers.findAndHookMethod(cls, "run", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) {
                    try {
                        int a = XposedHelpers.getIntField(p.thisObject, "a");
                        Object c = XposedHelpers.getObjectField(p.thisObject, "c");
                        if (a == 7 && c != null && MA.equals(c.getClass().getName())) {
                            XposedBridge.log(TAG + "  suppressed security Toast in a.Yj.run()");
                            p.setResult(null);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            });
            bound++;
            XposedBridge.log(TAG + "  bound   a.Yj.run() [security toast runner]");
            return true;
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  absent  a.Yj.run()");
            return false;
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
    /*  2b. guarded finish() suppressor on MainActivity                      */
    /* ===================================================================== */

    private static boolean hookActivityFinish(ClassLoader cl) {
        try {
            XposedHelpers.findAndHookMethod("android.app.Activity", cl, "finish",
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) {
                            if (p.thisObject != null && MA.equals(p.thisObject.getClass().getName())) {
                                if (isSecurityKill()) {
                                    XposedBridge.log(TAG + "  suppressed security kill on MainActivity.finish()");
                                    p.setResult(null);
                                }
                            }
                        }
                    });
            bound++;
            XposedBridge.log(TAG + "  bound   Activity.finish() [security suppressor]");
            return true;
        } catch (Throwable t) {
            skipped++;
            XposedBridge.log(TAG + "  skipped Activity.finish(): " + t);
            return false;
        }
    }

    private static boolean isSecurityKill() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            return true;
        }
        StackTraceElement[] st = new Throwable().getStackTrace();
        int n = Math.min(st.length, 30);
        for (int i = 0; i < n; i++) {
            String cn = st[i].getClassName();
            String mn = st[i].getMethodName();
            if (cn.contains("cs0") || cn.contains("Ja") || cn.contains("Yj")
                    || cn.contains("Pq0") || cn.contains("Ve0") || cn.contains("nb0")) {
                return true;
            }
            if (MA.equals(cn) && ("A1".equals(mn) || "B1".equals(mn) || "W1".equals(mn))) {
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
        boolean integ1866Pq0 = hookPq0(cl);
        boolean integ1866Ja = hookJa(cl);

        boolean integCovered = integPost || (integ1866Pq0 && integ1866Ja) || integConsumer;
        if (!integCovered) {
            criticalMissing = true;
            XposedBridge.log(TAG + "  MISS integrity hooks " + Arrays.toString(M_INTEGRITY)
                    + " / " + Arrays.toString(M_INTEGRITY_CONSUMER) + " / a.Pq0 / a.Ja");
        }

        /* tier 2: kill path (primary & fallback) */
        boolean kill1 = bindFirst(ma, M_KILL1, null, int.class);
        boolean kill2 = bindFirst(ma, M_KILL2, null, int.class, boolean.class);
        boolean killCs0 = hookCs0(cl);
        hookYj(cl);
        boolean finishSuppressed = hookActivityFinish(cl);

        bindFirst(ma, M_TOAST, null, int.class);
        bindFirst(ma, M_MONITOR_KILL, null);

        boolean killCovered = kill1 || kill2 || (killCs0 && finishSuppressed);
        if (!killCovered) {
            criticalMissing = true;
            XposedBridge.log(TAG + "  MISS kill-path hooks");
        }

        /* tier 3: individual probes */
        for (int i = 0; i < M_CHECKS_1866_NOARG.length; i++) {
            bind(ma, M_CHECKS_1866_NOARG[i], Boolean.FALSE);
        }
        for (int i = 0; i < M_CHECKS_1866_WITH_MA.length; i++) {
            bind(ma, M_CHECKS_1866_WITH_MA[i], Boolean.FALSE, ma);
        }
        for (int i = 0; i < M_CHECKS_1865.length; i++) {
            bindIfPresent(cl, MA, M_CHECKS_1865[i], Boolean.FALSE);
        }

        /* 18.6.6 external probes */
        bindIfPresent(cl, "a.HV", "r", Boolean.FALSE);
        bindIfPresent(cl, "a.Nm1", "a", Boolean.FALSE, Context.class);

        /* helpers used by the React Native bridge */
        bindIfPresent(cl, "net.omobio.dialogsc.Utils", "e", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.support.lib.RootInfoCallable", "call", Boolean.FALSE);

        /* legacy security package */
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityValidator",
                "isSecure", Boolean.TRUE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "performComprehensiveSecurityCheck", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isProductionSecure", Boolean.TRUE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isAdvancedRootDetected", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "hasRootManagementApps", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isDeveloperOptionsEnabled", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isEmulatorEnvironment", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isHooked", Boolean.FALSE);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isSSLPinningBypassed", Boolean.FALSE);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isSystemTampered", Boolean.FALSE);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isDebuggingDetected", Boolean.FALSE);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "isCodeTampered", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "performRuntimeChecks", Boolean.FALSE, Context.class);
        bindIfPresent(cl, "net.omobio.dialogsc.security.SecurityManager",
                "verifyAppSignature", Boolean.TRUE, Context.class);

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
