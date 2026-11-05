#!/usr/bin/env python3
"""Mark each org audit stamp CURRENT, STALE, UNKNOWN or NOT_CHECKABLE.

Usage:
  status.py <stamps-dir> --out audit/status.json [--org aien-dev] [--heads FILE]

For every public stamp the repository's default-branch HEAD is looked up with
`git ls-remote https://github.com/<org>/<repo> HEAD` (or read from --heads, a JSON
map repo -> sha, used by the tests). The newest stamp of a repository is

  CURRENT        HEAD equals the stamped commit
  STALE          HEAD has moved past the stamped commit
  UNKNOWN        HEAD could not be read; never treated as CURRENT
  NOT_CHECKABLE  private stamp (self-reported; nobody outside can read the HEAD)

Older stamps of the same repository are SUPERSEDED. The output carries no clock
time, so a run that sees the same HEADs writes the same bytes and the workflow
commits nothing.
"""
import argparse, json, os, re, subprocess, sys

SHA40 = re.compile(r"^[0-9a-f]{40}$")


def ls_remote_head(org, repo):
    try:
        p = subprocess.run(["git", "ls-remote", "https://github.com/%s/%s" % (org, repo), "HEAD"],
                           capture_output=True, text=True, timeout=60,
                           env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "ls-remote failed: %s" % type(e).__name__
    sha = p.stdout.split("\t", 1)[0].strip()
    if p.returncode != 0 or not SHA40.match(sha):
        return None, "ls-remote exit %d" % p.returncode
    return sha, ""


def collect(stamps_dir):
    by_id = {}
    if not os.path.isdir(stamps_dir):  # no stamps published yet
        return by_id
    for ident in sorted(os.listdir(stamps_dir)):
        d = os.path.join(stamps_dir, ident)
        if not os.path.isdir(d):
            continue
        for sha in sorted(os.listdir(d)):
            f = os.path.join(d, sha, "stamp.json")
            if os.path.isfile(f):
                with open(f) as fh:
                    st = json.load(fh)
                by_id.setdefault(ident, []).append(st)
    return by_id


def compute(stamps_dir, org, heads=None):
    rows = []
    for ident, sts in collect(stamps_dir).items():
        # newest = latest stamped_at date, then commit for a total order
        sts.sort(key=lambda s: (s.get("stamped_at", ""), s["subject"]["commit"]))
        newest = sts[-1]
        for st in sts[:-1]:
            rows.append({"id": ident, "commit": st["subject"]["commit"], "verdict": st.get("verdict"),
                         "state": "SUPERSEDED", "head": None, "note": "a newer stamp exists"})
        sub = newest["subject"]
        row = {"id": ident, "commit": sub["commit"], "verdict": newest.get("verdict")}
        if sub.get("visibility") == "private":
            row.update(state="NOT_CHECKABLE", head=None, note="private repository; stamp is self-reported")
        else:
            if heads is not None:
                head, why = heads.get(ident), "no HEAD supplied"
            else:
                head, why = ls_remote_head(org, ident)
            if not head:
                row.update(state="UNKNOWN", head=None, note=why)
            elif head == sub["commit"]:
                row.update(state="CURRENT", head=head, note="")
            else:
                row.update(state="STALE", head=head, note="default-branch HEAD moved past the stamped commit")
        rows.append(row)
    rows.sort(key=lambda r: (r["id"], r["state"] == "SUPERSEDED", r["commit"]))
    return {"schema": "aien-audit-status/1", "org": org, "stamps": rows}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stamps_dir")
    ap.add_argument("--out", required=True)
    ap.add_argument("--org", default="aien-dev")
    ap.add_argument("--heads", default="")
    a = ap.parse_args()
    heads = None
    if a.heads:
        with open(a.heads) as fh:
            heads = json.load(fh)
    doc = compute(a.stamps_dir, a.org, heads)
    data = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    with open(a.out, "w") as fh:
        fh.write(data)
    unknown = sum(r["state"] == "UNKNOWN" for r in doc["stamps"])
    print("stamps=%d stale=%d unknown=%d" % (len(doc["stamps"]), sum(r["state"] == "STALE" for r in doc["stamps"]), unknown))
    sys.exit(3 if unknown else 0)


if __name__ == "__main__":
    main()
