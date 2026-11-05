#!/usr/bin/env python3
"""Check an org audit stamp from outside.

Usage:
  verify.py <stamp-dir> [--rerun GITDIR] [--worktree DIR] [--tools DIR] [--salts FILE]

Step 1 always runs: stamp.py's validation (schema, verdict ceiling, file hashes).
Step 2 runs with --rerun: checks.py is run again at the stamped commit from GITDIR
(a clone of the stamped repository), and every check's output_sha256 must equal the
stamped value. A different checker or tools lock cannot reproduce the stamp, so that
case is reported as NOT_RUN rather than as a match or a mismatch.

Exit 0 verified, 1 invalid or mismatched, 2 NOT_RUN (could not reproduce).
"""
import argparse, json, os, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import checks  # noqa: E402
import stamp  # noqa: E402


def rerun(stamp_dir, gitdir, worktree, tools, lock_path=checks.LOCK_PATH):
    with open(os.path.join(stamp_dir, "stamp.json")) as fh:
        st = json.load(fh)
    dc = st["deterministic_checked"]
    _, lock_sha = checks.load_lock(lock_path)
    if dc.get("checker", {}).get("sha256") != checks.checker_sha256():
        return 2, ["stamp was made by checker %s; this checkout is %s" % (dc.get("checker", {}).get("sha256"),
                                                                          checks.checker_sha256())]
    if dc.get("tools_lock_sha256") != lock_sha:
        return 2, ["stamp used tools lock %s; this checkout has %s" % (dc.get("tools_lock_sha256"), lock_sha)]
    repo = st["subject"].get("repository") or st["subject"]["anonymous_id"]
    with tempfile.TemporaryDirectory(prefix="aien-verify-") as out:
        doc = checks.run_all(gitdir, st["subject"]["commit"], repo, out, dc.get("fork_base") or "", tools, worktree,
                             lock_path=lock_path)
    got = {c["check"]: c for c in doc["checks"]}
    errs = []
    skipped = []
    for c in dc["checks"]:
        g = got.get(c["check"])
        if c.get("reproducible") is False:
            skipped.append(c["check"])  # e.g. OSV advisories: an online database queried at stamp time
            continue
        if g is None:
            errs.append("%s: not produced by the rerun" % c["check"])
        elif g["status"] == "NOT_RUN" and c["status"] != "NOT_RUN":
            return 2, ["%s: tool unavailable here (%s)" % (c["check"], g.get("note", ""))]
        elif g["output_sha256"] != c["output_sha256"]:
            errs.append("%s: output %s, stamp says %s" % (c["check"], g["output_sha256"], c["output_sha256"]))
    if not errs and skipped:
        print("not reproducible by design, not compared: " + ", ".join(skipped), file=sys.stderr)
    return (1 if errs else 0), errs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("stamp_dir")
    ap.add_argument("--rerun", default="", help="git dir of the stamped repository")
    ap.add_argument("--worktree", default="")
    ap.add_argument("--tools", default=os.environ.get("AUDIT_TOOLS", HERE))
    ap.add_argument("--salts", default="")
    a = ap.parse_args()
    errs = stamp.validate(a.stamp_dir, a.salts or None)
    if errs:
        for e in errs:
            print("INVALID: " + e, file=sys.stderr)
        sys.exit(1)
    if not a.rerun:
        print("VALID (hashes and verdict ceiling); rerun NOT_RUN: pass --rerun GITDIR to reproduce the checks")
        sys.exit(0)
    code, msgs = rerun(a.stamp_dir, a.rerun, a.worktree, a.tools)
    for m in msgs:
        print(("MISMATCH: " if code == 1 else "NOT_RUN: ") + m, file=sys.stderr)
    if code == 0:
        print("VERIFIED " + a.stamp_dir)
    sys.exit(code)


if __name__ == "__main__":
    main()
