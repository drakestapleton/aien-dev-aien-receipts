#!/usr/bin/env python3
"""Validate an org audit stamp (schema aien-audit-stamp/1).

Usage:
  stamp.py validate <stamp-dir> [--salts FILE]

A stamp lives at audit/stamps/<repo-or-private-NN>/<sha>/stamp.json, next to the
checks/ directory written by checks.py and the review reports it cites. The rules
below are mechanical; they say what a stamp may claim, not whether a review is right.

  * verdict is one of PASS, PASS-WITH-NOTES, FAIL; no stamp text says "pristine",
    "approved", "certified" or "flawless".
  * deterministic_checked and model_reviewed are separate lists. Every check names
    tool, version, command and output_sha256; every review names agent role, model,
    effort, files covered and the sha256 of its report, which must be in the stamp dir.
  * the claimed verdict is never better than verdict_ceiling(): any open high or
    critical finding is FAIL; any NOT_RUN item, INCOMPLETE or NOT_RUN check,
    untriaged FLAGGED item, open finding, incomplete review, or no review at all
    caps the verdict at PASS-WITH-NOTES.
  * UPSTREAM-FORK subjects pin the upstream merge-base and the checks ran in fork-diff
    mode against that same base.
  * private subjects carry only an anonymous id (private-01 .. private-99) and a
    salted SHA-256 commitment; with --salts, the real names must not appear anywhere.

Exit 0 valid, 1 invalid (reasons on stderr), 2 usage error.
"""
import argparse, hashlib, json, os, re, sys

SCHEMA = "aien-audit-stamp/1"
VERDICTS = ("PASS", "PASS-WITH-NOTES", "FAIL")
RANK = {"PASS": 0, "PASS-WITH-NOTES": 1, "FAIL": 2}
FORBIDDEN = re.compile(r"\b(pristine|approved|certified|flawless)\b", re.I)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
ANON = re.compile(r"^private-\d{2}$")
KINDS = ("FIRST-PARTY", "UPSTREAM-FORK", "ARCHIVED")
CHECK_STATUS = ("PASS", "FLAGGED", "INCOMPLETE", "NOT_RUN")
FINDING_STATUS = ("OPEN", "FIXED", "ACCEPTED", "FALSE-POSITIVE")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def strings(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from strings(v)


def verdict_ceiling(st):
    """Best verdict the stamp's own contents allow, with the reasons that capped it."""
    reasons = []
    findings = st.get("findings", [])
    if any(f.get("status") == "OPEN" and f.get("severity") in ("critical", "high") for f in findings):
        return "FAIL", ["open critical/high finding"]
    if st.get("not_run"):
        reasons.append("%d NOT_RUN item(s)" % len(st["not_run"]))
    for c in st.get("deterministic_checked", {}).get("checks", []):
        if c.get("status") in ("NOT_RUN", "INCOMPLETE"):
            reasons.append("check %s is %s" % (c.get("check"), c.get("status")))
        elif c.get("status") == "FLAGGED" and c.get("triaged", 0) < (c.get("count") or 0):
            reasons.append("check %s has %d untriaged item(s)" % (c.get("check"), (c.get("count") or 0) - c.get("triaged", 0)))
    if any(f.get("status") == "OPEN" for f in findings):
        reasons.append("open finding(s)")
    reviews = st.get("model_reviewed", [])
    if not reviews:
        reasons.append("no model review")
    for r in reviews:
        if not r.get("complete"):
            reasons.append("review %s/%s incomplete (%s of %s files)" % (r.get("agent_role"), r.get("model"),
                                                                           r.get("files_covered"), r.get("files_total")))
    return ("PASS-WITH-NOTES" if reasons else "PASS"), reasons


def validate(stamp_dir, salts=None):
    errs = []
    path = os.path.join(stamp_dir, "stamp.json")
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        st = json.loads(raw)
    except (OSError, ValueError) as e:
        return ["cannot read stamp.json: %s" % e]
    if st.get("schema") != SCHEMA:
        errs.append("schema must be %s" % SCHEMA)
    for s in strings(st):
        m = FORBIDDEN.search(s)
        if m:
            errs.append("forbidden word %r in stamp text" % m.group(0))
            break
    sub = st.get("subject", {})
    commit = sub.get("commit", "")
    if not SHA40.match(commit):
        errs.append("subject.commit must be a full 40-hex sha")
    if os.path.basename(os.path.normpath(stamp_dir)) != commit:
        errs.append("stamp directory name must equal subject.commit")
    if not SHA40.match(sub.get("tree", "")):
        errs.append("subject.tree must be a full 40-hex sha")
    if sub.get("kind") not in KINDS:
        errs.append("subject.kind must be one of %s" % ", ".join(KINDS))
    ident = os.path.basename(os.path.dirname(os.path.normpath(stamp_dir)))
    if sub.get("visibility") == "private":
        if "repository" in sub:
            errs.append("private subject must not carry a repository name")
        if not ANON.match(sub.get("anonymous_id", "")) or sub.get("anonymous_id") != ident:
            errs.append("private subject needs anonymous_id private-NN equal to the stamp's parent directory")
        if not SHA64.match(sub.get("name_commitment", "")):
            errs.append("private subject needs a 64-hex name_commitment")
        if st.get("self_reported") is not True:
            errs.append("private stamp must set self_reported: true")
    elif sub.get("visibility") == "public":
        if sub.get("repository") != ident:
            errs.append("public subject.repository must equal the stamp's parent directory")
        if "anonymous_id" in sub or "name_commitment" in sub:
            errs.append("public subject must not carry anonymous fields")
    else:
        errs.append("subject.visibility must be public or private")
    dc = st.get("deterministic_checked", {})
    if sub.get("kind") == "UPSTREAM-FORK":
        up = sub.get("upstream", {})
        if not up.get("repository") or not SHA40.match(up.get("base_sha", "")):
            errs.append("UPSTREAM-FORK needs upstream.repository and a 40-hex upstream.base_sha")
        elif dc.get("mode") != "fork-diff" or dc.get("fork_base") != up.get("base_sha"):
            errs.append("UPSTREAM-FORK checks must run in fork-diff mode against upstream.base_sha")
    checks = dc.get("checks")
    if not isinstance(checks, list) or not checks:
        errs.append("deterministic_checked.checks must be a non-empty list")
        checks = []
    for c in checks:
        for k in ("check", "tool", "version", "command", "output_sha256", "status"):
            if k not in c:
                errs.append("check %s lacks %s" % (c.get("check", "?"), k))
        if c.get("status") not in CHECK_STATUS:
            errs.append("check %s has status %r" % (c.get("check"), c.get("status")))
        if c.get("output_sha256") and not SHA64.match(c["output_sha256"]):
            errs.append("check %s output_sha256 is not 64 hex" % c.get("check"))
        f = os.path.join(stamp_dir, "checks", "%s.json" % c.get("check"))
        if os.path.exists(f):
            with open(f, "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != c.get("output_sha256"):
                    errs.append("checks/%s.json does not match its output_sha256" % c.get("check"))
        elif c.get("status") != "NOT_RUN":
            errs.append("checks/%s.json missing" % c.get("check"))
    for r in st.get("model_reviewed", []):
        for k in ("agent_role", "model", "effort", "files_covered", "files_total", "report", "report_sha256", "complete"):
            if k not in r:
                errs.append("review lacks %s" % k)
        rp = os.path.normpath(os.path.join(stamp_dir, r.get("report", "")))
        if not rp.startswith(os.path.normpath(stamp_dir) + os.sep):
            errs.append("review report %r is outside the stamp directory" % r.get("report"))
        elif not os.path.exists(rp):
            errs.append("review report %s missing" % r.get("report"))
        else:
            with open(rp, "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != r.get("report_sha256"):
                    errs.append("review report %s does not match report_sha256" % r.get("report"))
        if r.get("complete") and r.get("files_covered") != r.get("files_total"):
            errs.append("review marked complete but covers %s of %s files" % (r.get("files_covered"), r.get("files_total")))
    for f in st.get("findings", []):
        if f.get("source") not in ("DETERMINISTIC", "MODEL"):
            errs.append("finding %s source must be DETERMINISTIC or MODEL" % f.get("id"))
        if f.get("status") not in FINDING_STATUS:
            errs.append("finding %s status must be one of %s" % (f.get("id"), ", ".join(FINDING_STATUS)))
        if f.get("severity") not in SEVERITIES:
            errs.append("finding %s severity must be one of %s" % (f.get("id"), ", ".join(SEVERITIES)))
        if f.get("status") == "FIXED" and not f.get("fix"):
            errs.append("finding %s is FIXED without a fix reference" % f.get("id"))
    for n in st.get("not_run", []):
        if not n.get("item") or not n.get("reason"):
            errs.append("not_run entries need item and reason")
    v = st.get("verdict")
    if v not in VERDICTS:
        errs.append("verdict must be one of %s" % ", ".join(VERDICTS))
    else:
        ceil, why = verdict_ceiling(st)
        if RANK[v] < RANK[ceil]:
            errs.append("verdict %s is better than the contents allow (%s: %s)" % (v, ceil, "; ".join(why)))
    if salts:
        with open(salts) as fh:
            sd = json.load(fh)  # {"private-NN": {"name", "salt", "commitment"}}, kept off the shelf at mode 0600
        low = raw.decode("utf-8", "replace").lower()
        for e in sd.values():
            if re.search(r"(?<![a-z0-9_.-])%s(?![a-z0-9_-])" % re.escape(e["name"].lower()), low):
                errs.append("a private repository name appears in the stamp")
                break
        if sub.get("visibility") == "private":
            ent = sd.get(sub.get("anonymous_id"))
            if not ent or commitment(ent["salt"], ent["name"]) != sub.get("name_commitment"):
                errs.append("name_commitment does not match the private salt record")
    return errs


def commitment(salt, name):
    """sha256("<salt hex>:<repository name>"), the form used when the salts were drawn on 2026-10-26."""
    return hashlib.sha256(f"{salt}:{name}".encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    v = sp.add_parser("validate")
    v.add_argument("stamp_dir")
    v.add_argument("--salts", default="")
    a = ap.parse_args()
    errs = validate(a.stamp_dir, a.salts or None)
    for e in errs:
        print("INVALID: " + e, file=sys.stderr)
    if not errs:
        print("VALID " + a.stamp_dir)
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
