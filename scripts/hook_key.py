"""Frida hook nt_sqlite3_key_v2, capture the QQ NT database key.

usage:
    python hook_key.py --rva 0x21b8c80 [--seconds 300]
"""
import argparse
import time

import frida

JS = r"""
var mod = Process.findModuleByName('wrapper.node');
if (mod === null) {
    send({ t: 'nomodule' });
} else {
    Interceptor.attach(mod.base.add(RVA), {
        onEnter: function (args) {
            try {
                var n = args[3].toInt32();
                var ab = args[2].readByteArray(n);
                var u8 = new Uint8Array(ab);
                var bytes = [];
                for (var i = 0; i < u8.length; i++) bytes.push(u8[i]);
                var zdb = '';
                try { zdb = args[1].isNull() ? '' : args[1].readUtf8String(); } catch (e) {}
                send({ t: 'hit', n: n, zdb: zdb, b: bytes });
            } catch (e) {
                send({ t: 'err', m: e.toString() });
            }
        }
    });
    send({ t: 'ok' });
}
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rva", required=True)
    ap.add_argument("--seconds", type=int, default=300)
    args = ap.parse_args()

    device = frida.get_local_device()
    procs = [p for p in device.enumerate_processes() if p.name.lower() == "qq.exe"]
    if not procs:
        raise SystemExit("QQ.exe is not running; log in first")

    script_src = JS.replace("RVA", args.rva)
    found: dict[int, str] = {}
    sessions = []

    def make_handler(pid):
        def handler(message, _data):
            if message.get("type") != "send":
                return
            payload = message["payload"]
            kind = payload.get("t")
            if kind == "hit":
                key = bytes(payload["b"]).decode("latin-1")
                found[payload["n"]] = key
                note = {16: "chat db key", 20: "login.db key, not the target"}.get(payload["n"], "unknown")
                print("HIT pid=%s n=%s zdb=%r key=%r (%s)" % (pid, payload["n"], payload.get("zdb"), key, note), flush=True)
            elif kind == "ok":
                print("injected into pid=%s" % pid, flush=True)
            elif kind == "err":
                print("hook error:", payload.get("m"), flush=True)
        return handler

    for proc in procs:
        try:
            session = frida.attach(proc.pid)
            script = session.create_script(script_src)
            script.on("message", make_handler(proc.pid))
            script.load()
            sessions.append((session, script))
        except Exception as exc:
            print("attach %s failed: %s" % (proc.pid, exc), flush=True)

    if not sessions:
        raise SystemExit("could not inject into any QQ process")

    deadline = time.time() + args.seconds
    while time.time() < deadline and 16 not in found:
        time.sleep(1)

    for session, script in sessions:
        for closer in (script.unload, session.detach):
            try:
                closer()
            except Exception:
                pass

    if 16 in found:
        print("KEY = " + found[16])
    else:
        print("no 16-byte key captured; open some chats in QQ to trigger a new db connection, or raise --seconds")


if __name__ == "__main__":
    main()
