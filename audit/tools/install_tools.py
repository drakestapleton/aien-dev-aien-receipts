#!/usr/bin/env python3
"""Install the pinned audit tools into DIR, refusing anything whose sha256 differs from tools.lock.json.

Usage: install_tools.py DIR [--arch linux_amd64|linux_arm64]

Downloads each binary named in the lock and checks the publisher's sha256 before
unpacking; installs semgrep and zizmor into DIR/venv with exact == version pins
(pip does not hash-check these; checks.py re-checks the printed versions); fetches semgrep-rules at the locked commit and rebuilds
semgrep-config.yaml (semgrep_config.py checks its sha256); fetches crumb.c at the
locked commit, checks its sha256 and builds DIR/crumb-arch. Exit 1 on any mismatch.
"""
import argparse, hashlib, io, json, os, platform, shutil, subprocess, sys, tarfile, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def run(*cmd, **kw):
    subprocess.run(cmd, check=True, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--arch", default={"x86_64": "linux_amd64", "aarch64": "linux_arm64"}.get(platform.machine(), ""))
    ap.add_argument("--only", default="", help="comma-separated binary names; skips pip, semgrep-rules and crumb")
    a = ap.parse_args()
    with open(os.path.join(HERE, "tools.lock.json")) as fh:
        lock = json.load(fh)
    os.makedirs(a.dir, exist_ok=True)
    only = set(filter(None, a.only.split(",")))
    for name, t in lock["tools"].items():
        if only and name not in only:
            continue
        if "downloads" in t:
            d = t["downloads"].get(a.arch)
            if not d:
                sys.exit("%s: no pinned download for %s" % (name, a.arch))
            data = fetch(d["url"])
            got = hashlib.sha256(data).hexdigest()
            if got != d["sha256"]:
                sys.exit("%s: sha256 %s != lock %s" % (name, got, d["sha256"]))
            dest = os.path.join(a.dir, name)
            if "member" in d:
                with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                    m = tf.getmember(d["member"])
                    with tf.extractfile(m) as src, open(dest, "wb") as out:
                        shutil.copyfileobj(src, out)
            else:
                with open(dest, "wb") as out:
                    out.write(data)
            os.chmod(dest, 0o755)
            print("%s %s %s" % (got, name, t["version"]))
    if only:
        return
    venv = os.path.join(a.dir, "venv")
    run(sys.executable, "-m", "venv", venv)
    pins = [t["pip"] for t in lock["tools"].values() if "pip" in t] + ["pyyaml==" + lock["semgrep_rules"]["pyyaml"]]
    run(os.path.join(venv, "bin", "pip"), "install", "--quiet", *pins)
    sr = lock["semgrep_rules"]
    rules = os.path.join(a.dir, "semgrep-rules")
    run("git", "init", "-q", rules)
    run("git", "-C", rules, "fetch", "-q", "--depth", "1", sr["repository"], sr["commit"])
    run("git", "-C", rules, "checkout", "-q", "FETCH_HEAD")
    run(os.path.join(venv, "bin", "python"), os.path.join(HERE, "semgrep_config.py"), rules,
        os.path.join(a.dir, "semgrep-config.yaml"))
    cr = lock["crumb"]
    url = cr["repository"].replace("https://github.com/", "https://raw.githubusercontent.com/") + "/%s/%s" % (cr["commit"], cr["source"])
    src = fetch(url)
    got = hashlib.sha256(src).hexdigest()
    if got != cr["source_sha256"]:
        sys.exit("crumb.c sha256 %s != lock %s" % (got, cr["source_sha256"]))
    with open(os.path.join(a.dir, "crumb.c"), "wb") as fh:
        fh.write(src)
    run("cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o", os.path.join(a.dir, "crumb-arch"),
        os.path.join(a.dir, "crumb.c"))
    print("%s crumb.c" % got)


if __name__ == "__main__":
    main()
