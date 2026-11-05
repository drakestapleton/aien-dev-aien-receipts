#!/usr/bin/env python3
"""Build semgrep-config.yaml from a semgrep-rules checkout pinned in tools.lock.json.

Usage: semgrep_config.py <semgrep-rules-checkout> <out.yaml>

Takes every rule file under the locked directories (test files excluded), keeps
rules whose severity is in the locked list, and writes one YAML document with
PyYAML's safe_dump(sort_keys=True). Exits 1 unless the checkout is at the locked
commit, PyYAML is the locked version and the output sha256 equals config_sha256.
"""
import glob, hashlib, json, os, subprocess, sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))


def build(root, lock):
    sr = lock["semgrep_rules"]
    rules = []
    for d in sr["directories"]:
        for p in sorted(glob.glob(os.path.join(root, d, "**", "*.yaml"), recursive=True)):
            if p.endswith(".test.yaml") or "/tests/" in p:
                continue
            try:
                with open(p) as fh:
                    doc = yaml.safe_load(fh)
            except yaml.YAMLError:
                continue
            if not isinstance(doc, dict) or "rules" not in doc:
                continue
            rules += [r for r in doc["rules"] if r.get("severity") in sr["severities"]]
    return yaml.safe_dump({"rules": rules}, sort_keys=True).encode()


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    root, out = sys.argv[1], sys.argv[2]
    with open(os.path.join(HERE, "tools.lock.json")) as fh:
        lock = json.load(fh)
    sr = lock["semgrep_rules"]
    head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != sr["commit"]:
        sys.exit("semgrep-rules checkout is at %r, lock wants %s" % (head, sr["commit"]))
    if yaml.__version__ != sr["pyyaml"]:
        sys.exit("PyYAML %s, lock wants %s" % (yaml.__version__, sr["pyyaml"]))
    data = build(root, lock)
    got = hashlib.sha256(data).hexdigest()
    if got != sr["config_sha256"]:
        sys.exit("built config sha256 %s != lock %s" % (got, sr["config_sha256"]))
    with open(out, "wb") as fh:
        fh.write(data)
    print("%s %s" % (got, out))


if __name__ == "__main__":
    main()
