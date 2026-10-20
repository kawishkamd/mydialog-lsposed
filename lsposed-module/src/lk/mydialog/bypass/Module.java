package lk.mydialog.bypass;

import android.content.Context;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Neutralises the two security gates in Dialog Self Care (net.omobio.dialogsc):
 *
 *   1. the root / tamper gate in MainActivity.Z1() + a2()  (adb, developer
 *      options, Magisk, Frida, debugger, emulator, taint, monkey, Xposed)
 *   2. the integrity gate: b2() POSTs the Play Integrity token to Dialog's
 *      server and acts on its answer -> we force it to succeed
 *
 * plus the toast + finish() paths so nothing can close the app.
 */
public class Module implements IXposedHookLoadPackage {

    private static final String TAG = "MyDialogBypass: ";
    private static final String PKG = "net.omobio.dialogsc";

    private static void hook(Class<?> cls, String name, Object value, Object... params) {
        try {
            Object[] args = new Object[params.length + 1];
            System.arraycopy(params, 0, args, 0, params.length);
            args[params.length] = XC_MethodReplacement.returnConstant(value);
            XposedHelpers.findAndHookMethod(cls, name, args);
            XposedBridge.log(TAG + "hooked " + name);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "skip " + name + " (" + t + ")");
        }
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lp) {
        if (!PKG.equals(lp.packageName)) {
            return;
        }
        XposedBridge.log(TAG + "loading for " + PKG);
        ClassLoader cl = lp.classLoader;

        Class<?> ma;
        try {
            ma = XposedHelpers.findClass("net.omobio.dialogsc.MainActivity", cl);
        } catch (Throwable t) {
            XposedBridge.log(TAG + "MainActivity not found: " + t);
            return;
        }

        /* 1) integrity verdict -- ignore the server's "false" */
        hook(ma, "b2", Boolean.TRUE, String.class, String.class);

        /* 2) root / tamper checks -> always clean */
        for (String m : new String[]{"N1", "J1", "E1", "L1", "D1", "F1", "M1",
                "G1", "I1", "H1", "O1", "x1", "y1"}) {
            hook(ma, m, Boolean.FALSE);
        }

        /* 3) toast + finish() paths -> no-op */
        hook(ma, "A1", null, int.class);
        hook(ma, "B1", null, int.class, boolean.class);
        hook(ma, "U1", null, int.class);
        hook(ma, "V1", null, int.class);
        hook(ma, "W1", null);

        /* 4) the helpers the React Native side uses */
        try {
            hook(XposedHelpers.findClass("net.omobio.dialogsc.Utils", cl),
                    "e", Boolean.FALSE, Context.class);
        } catch (Throwable ignored) {
        }
        try {
            hook(XposedHelpers.findClass("net.omobio.dialogsc.support.lib.RootInfoCallable", cl),
                    "call", Boolean.FALSE);
        } catch (Throwable ignored) {
        }
        try {
            hook(XposedHelpers.findClass("net.omobio.dialogsc.security.SecurityValidator", cl),
                    "isSecure", Boolean.TRUE, Context.class);
        } catch (Throwable ignored) {
        }
        try {
            Class<?> sm = XposedHelpers.findClass("net.omobio.dialogsc.security.SecurityManager", cl);
            hook(sm, "performComprehensiveSecurityCheck", Boolean.FALSE, Context.class);
            hook(sm, "isProductionSecure", Boolean.TRUE, Context.class);
        } catch (Throwable ignored) {
        }
        try {
            Class<?> sma = XposedHelpers.findClass("net.omobio.dialogsc.SecurityManagerAdvance", cl);
            hook(sma, "performSecurityCheck", Boolean.FALSE);
            hook(sma, "checkFridaLibs", Boolean.FALSE);
            hook(sma, "checkFridaPort", Boolean.FALSE);
            hook(sma, "checkFridaServer", Boolean.FALSE);
        } catch (Throwable ignored) {
        }

        XposedBridge.log(TAG + "armed");
    }
}
