#!/usr/bin/env python3
"""THROWAWAY HOST TOOLING: orchestrates the frozen PROTOCOL.md benchmark. Statistics are NOT done here
(Wolfram does them from raw.jsonl). Usage: run.py BIN_DIR WWW_DIR OUT_DIR [ROUNDS] [CPUS]"""
import hashlib, json, os, random, subprocess, sys, time

BIN, WWW, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
ROUNDS = int(sys.argv[4]) if len(sys.argv) > 4 else 30
CPUS = [int(c) for c in (sys.argv[5] if len(sys.argv) > 5 else "16,2").split(",")]
SERVER_CPU = 18
SUITES = {"chacha": "TLS_CHACHA20_POLY1305_SHA256", "aes128gcm": "TLS_AES_128_GCM_SHA256"}
ARMS = {
    "omega": ([f"{BIN}/omega"], {}),
    "omega-asis": ([f"{BIN}/omega-asis"], {}),
    "openssl": ([f"{BIN}/openssl"], {}),
    "rustls-awslc": ([f"{BIN}/rustls"], {"BENCH_PROVIDER": "aws-lc-rs"}),
    "rustls-ring": ([f"{BIN}/rustls"], {"BENCH_PROVIDER": "ring"}),
}
# id: (mode, path, frag, n, warmup)
WORK = {
    "hs": ("h", "small.bin", 16384, 40, 5),
    "get1k": ("g", "small.bin", 16384, 20, 3),
    "get1m": ("g", "1m.bin", 16384, 8, 2),
    "bulk16k": ("b", "16m.bin", 16384, 3, 1),
    "bulk1k": ("b", "16m.bin", 1024, 3, 1),
}
os.makedirs(OUT, exist_ok=True)
servers, ports = [], {}


def start_servers():
    port = 15920
    for s, name in SUITES.items():
        for frag in (16384, 1024):
            port += 1
            cmd = ["taskset", "-c", str(SERVER_CPU), "openssl", "s_server", "-accept", f"127.0.0.1:{port}",
                   "-cert", "leaf.pem", "-key", "leaf.key", "-tls1_3", "-ciphersuites", name,
                   "-groups", "X25519", "-no_ticket", "-WWW", "-quiet", "-max_send_frag", str(frag)]
            servers.append(subprocess.Popen(cmd, cwd=WWW, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, stderr=open(f"{OUT}/server-{port}.log", "w")))
            ports[(s, frag)] = port
    time.sleep(1.5)


def run_ru(arm, cpu, mode, port, n, path):
    """fork+exec under GNU time: peak RSS and CPU of the client itself, not of the forked Python image"""
    argv, env = ARMS[arm]
    e = dict(os.environ, **env)
    r, w = os.pipe()
    r2, w2 = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.chdir(WWW)
        os.dup2(w, 1); os.dup2(w2, 2)
        os.close(r); os.close(r2)
        os.execvpe("/usr/bin/time", ["/usr/bin/time", "-f", "RUSAGE %M %U %S", "taskset", "-c", str(cpu)] + argv + [mode, str(port), str(n), path, "root.pem"], e)
    os.close(w); os.close(w2)
    out = b""
    with os.fdopen(r, "rb") as f:
        out = f.read()
    with os.fdopen(r2, "rb") as f:
        err = f.read()
    _, status, ru = os.wait4(pid, 0)
    return os.waitstatus_to_exitcode(status), out, err, ru


def cpu_busy():
    d = {}
    for line in open("/proc/stat"):
        if line.startswith("cpu") and line[3].isdigit():
            f = line.split()
            c = int(f[0][3:])
            v = list(map(int, f[1:]))
            d[c] = (sum(v) - v[3] - v[4], sum(v))
    return d


def gate():
    res = []
    want = {p: hashlib.sha256(open(f"{WWW}/{p}", "rb").read()).hexdigest() for p in ("1m.bin", "16m.bin")}
    for s in SUITES:
        for arm in ARMS:
            for path, frag in (("1m.bin", 16384), ("16m.bin", 1024)):
                rc, out, err, _ = run_ru(arm, CPUS[0], "d", ports[(s, frag)], 1, path)
                i = out.find(b"\r\n\r\n")
                h = hashlib.sha256(out[i + 4:]).hexdigest() if i >= 0 else ""
                ok = rc == 0 and h == want[path]
                res.append({"suite": s, "arm": arm, "path": path, "frag": frag, "rc": rc, "sha256": h, "ok": ok,
                            "err": err.decode(errors="replace")[-300:]})
    json.dump(res, open(f"{OUT}/gate.json", "w"), indent=1)
    return {(r["suite"], r["arm"]) for r in res if not r["ok"]}


def main():
    start_servers()
    try:
        bad = gate()
        print("gate failures:", sorted(bad), flush=True)
        raw = open(f"{OUT}/raw.jsonl", "a")
        for cpu in CPUS:
            for s in SUITES:
                for rnd in range(ROUNDS):
                    order = list(ARMS)
                    random.Random(cpu * 100000 + rnd * 10 + len(s)).shuffle(order)  # fixed, published seed
                    b0 = cpu_busy(); l0 = open("/proc/loadavg").read().split()[0]
                    for arm in order:
                        if (s, arm) in bad:
                            continue
                        for wid, (mode, path, frag, n, warm) in WORK.items():
                            t = time.time()
                            rc, out, err, ru = run_ru(arm, cpu, mode, ports[(s, frag)], n, path)
                            ru_l = [l.split() for l in err.decode(errors="replace").splitlines() if l.startswith("RUSAGE ")]
                            maxrss, cpu_s = (int(ru_l[-1][1]), float(ru_l[-1][2]) + float(ru_l[-1][3])) if ru_l else (None, None)
                            samp = [tuple(map(int, l.split()[1:3])) for l in out.decode().splitlines() if l.startswith("S ")]
                            raw.write(json.dumps({"cpu": cpu, "suite": s, "round": rnd, "arm": arm, "work": wid, "rc": rc,
                                                  "ns": [x[0] for x in samp], "bytes": [x[1] for x in samp], "warm": warm,
                                                  "maxrss_kib": maxrss, "cpu_s": cpu_s,
                                                  "t": t, "err": err.decode(errors="replace")[-200:]}) + "\n")
                    b1 = cpu_busy(); l1 = open("/proc/loadavg").read().split()[0]
                    busy = {c: round((b1[c][0] - b0[c][0]) / max(1, b1[c][1] - b0[c][1]), 3) for c in (16, 2, 18)}
                    raw.write(json.dumps({"cpu": cpu, "suite": s, "round": rnd, "env": True, "order": order,
                                          "load_start": l0, "load_end": l1, "busy": busy}) + "\n")
                    raw.flush()
                    print(f"cpu{cpu} {s} round {rnd} done load {l1}", flush=True)
    finally:
        for p in servers:
            p.terminate()


main()
