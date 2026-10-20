#!/usr/bin/env python3
"""
Attach Frida to MyDialog and install the anti-tamper bypass.

Why two phases?
  Frida cannot *spawn* on this device (frida-server's spawn helper fails), and
  attaching right after launch is a race: the app runs its Root/Tamper checks
  ~1.5s after start, which is often before the hooks are installed.

  So we:
    1. make sure the app process is alive (it may already have shown its error
       and closed the activity, but the process survives),
    2. attach to that live process and install the hooks,
    3. start the activity again -- onCreate/onResume then run with the hooks
       already in place, so the app comes up normally.

Keep this process running while you use the app: detaching removes the hooks
and the app will slam shut on the next check (it re-checks on every resume).
"""

import os
import subprocess
import sys
import time

import frida

PKG = "net.omobio.dialogsc"
ACT = PKG + "/.MainActivity"
HERE = os.path.dirname(os.path.abspath(__file__))
JS = open(os.path.join(HERE, "bypass.js")).read()

DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 86400


def on_message(message, data):
    if message.get("type") == "send":
        print(message["payload"], flush=True)
    else:
        print("!!", message.get("description") or message.get("stack"), flush=True)


def start_app():
    subprocess.run(["adb", "shell", "am", "start", "-n", ACT],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def pid_of():
    out = subprocess.run(["adb", "shell", "pidof", PKG],
                         capture_output=True, text=True).stdout.strip()
    return int(out.split()[0]) if out else None


def main():
    dev = frida.get_usb_device(timeout=15)

    print("[1/3] making sure MyDialog is running ...", flush=True)
    pid = pid_of()
    if pid is None:
        start_app()
        for _ in range(30):
            time.sleep(0.5)
            pid = pid_of()
            if pid:
                break
    if pid is None:
        sys.exit("could not start MyDialog")
    print("      pid =", pid, flush=True)

    print("[2/3] attaching and installing hooks ...", flush=True)
    session = None
    script = None
    deadline = time.time() + 40
    while time.time() < deadline:
        if session is None:
            p = pid_of()
            if p is None:
                time.sleep(0.3)
                continue
            try:
                session = dev.attach(p)
            except Exception:
                time.sleep(0.3)
                continue
        try:
            script = session.create_script(JS)
            script.on("message", on_message)
            script.load()
            break
        except Exception as exc:
            print("      retrying:", exc, flush=True)
            try:
                session.detach()
            except Exception:
                pass
            session = None
            script = None
            time.sleep(0.3)

    if script is None:
        sys.exit("could not attach to MyDialog")

    print("[3/3] starting the app with the bypass active ...", flush=True)
    start_app()
    time.sleep(5)
    print("\nMyDialog should now be on screen. Keep this window open.\n"
          "Ctrl-C to stop (the app will close itself again once stopped).\n", flush=True)
    try:
        time.sleep(DUR)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
