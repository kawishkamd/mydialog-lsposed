/*
 * MyDialog (net.omobio.dialogsc) anti-tamper bypass.
 *
 * The app has two gates:
 *
 *   1) A "root / tamper" gate in MainActivity.Z1() + MainActivity.a2()
 *      which checks: adb enabled, developer options, su binaries, Magisk paths,
 *      Frida (files, /proc/self/maps, ports 27042-27046, `ps`), debugger,
 *      emulator, taint tracking, monkey, Xposed.
 *      If ANY is true it shows a Toast and calls finish().
 *
 *   2) An "integrity" gate: MainActivity.T1() asks Play Integrity for a token,
 *      then MainActivity.b2() POSTs it to Dialog's server
 *      (https://selfcare.dialog.lk/.../verifyIntegrityToken) which returns
 *      {"success":true|false}. On false it shows a Toast and calls finish().
 *      The verdict is therefore decided server-side, so a valid keybox cannot
 *      help here -- the client's interpretation of the answer is what we patch.
 *
 * This script neutralises both gates while it is attached.
 */
Java.perform(function () {
    var log = function (s) { send(s); };
    var MAS;
    try {
        MAS = Java.use('net.omobio.dialogsc.MainActivity');
    } catch (e) {
        log('!! cannot find MainActivity: ' + e);
        return;
    }

    /* ---- 1) integrity verdict: do not trust the server's "false" ---- */
    try {
        MAS.b2.overload('java.lang.String', 'java.lang.String').implementation = function () {
            log('== [bypass] integrity verdict -> true');
            return true;
        };
    } catch (e) { log('b2 hook failed: ' + e); }

    /* ---- 2) root / tamper checks -> always "clean" ---- */
    ['N1', 'J1', 'E1', 'L1', 'D1', 'F1', 'M1', 'G1', 'I1', 'H1', 'O1',
     'x1', 'y1'].forEach(function (name) {
        try {
            MAS[name].overload().implementation = function () {
                var real = false;
                try { real = this[name](); } catch (e) { }
                log('== [bypass] ' + name + '() ' + real + ' -> false');
                return false;
            };
        } catch (e) { log(name + ' hook failed: ' + e); }
    });

    /* ---- 3) root-info helper used by Utils.e() ---- */
    try {
        Java.use('net.omobio.dialogsc.Utils').e
            .overload('android.content.Context').implementation = function () { return false; };
    } catch (e) { }
    try {
        Java.use('net.omobio.dialogsc.support.lib.RootInfoCallable').call
            .overload().implementation = function () { return false; };
    } catch (e) { }

    /* ---- 4) the "show a Toast then finish()" paths ---- */
    try {
        MAS.A1.overload('int').implementation = function (id) { log('== [bypass] blocked A1(' + id + ')'); };
    } catch (e) { }
    try {
        MAS.B1.overload('int', 'boolean').implementation = function (id, z) { log('== [bypass] blocked B1(' + id + ',' + z + ')'); };
    } catch (e) { }
    try {
        MAS.W1.overload().implementation = function () { log('== [bypass] blocked W1()'); };
    } catch (e) { }
    try {
        MAS.U1.overload('int').implementation = function (id) { log('== [bypass] blocked U1(' + id + ')'); };
    } catch (e) { }
    try {
        MAS.V1.overload('int').implementation = function (id) { log('== [bypass] blocked V1(' + id + ')'); };
    } catch (e) { }

    /* ---- 5) the JS-facing security helpers ---- */
    try {
        Java.use('net.omobio.dialogsc.security.SecurityValidator').isSecure
            .overload('android.content.Context').implementation = function () { return true; };
    } catch (e) { }
    try {
        var SM = Java.use('net.omobio.dialogsc.security.SecurityManager');
        SM.performComprehensiveSecurityCheck
            .overload('android.content.Context').implementation = function () { return false; };
        SM.isProductionSecure
            .overload('android.content.Context').implementation = function () { return true; };
    } catch (e) { }
    try {
        var SMA = Java.use('net.omobio.dialogsc.SecurityManagerAdvance');
        SMA.performSecurityCheck.overload().implementation = function () { return false; };
        SMA.checkFridaLibs.overload().implementation = function () { return false; };
        SMA.checkFridaPort.overload().implementation = function () { return false; };
        SMA.checkFridaServer.overload().implementation = function () { return false; };
    } catch (e) { }

    log('== [bypass] armed ==');
});
