#!/usr/bin/env python3
"""Deterministic audit checks for one repository at one commit.

Usage:
  checks.py <git-dir> <sha> --repo NAME --out DIR [--fork-base SHA] [--tools DIR] [--worktree DIR] [--only C1,C5]

The tree is read raw from git objects (loc.materialize), never checked out.
Each check writes DIR/<id>.json (normalized, sorted, no timestamps) and the
summary DIR/checks.json lists, per check: tool and version, the exact command,
status, counts, the sha256 of exactly the bytes written to DIR/<id>.json, and
whether a second run on another machine must give the same hash (reproducible)
or is a dated snapshot (advisory databases).

Tools are pinned in tools.lock.json; a tool whose printed version differs from
the lock is treated as missing, so a result is never produced by an unpinned tool.

Status values:
  PASS        tool ran over every target and reported nothing
  FLAGGED     tool ran and reported items; each needs triage (recorded as findings in the stamp)
  INCOMPLETE  tool ran but some targets were not analysed (parse errors, timeouts, one of two
              scanners missing); the gaps are listed. Never counts as PASS.
  NOT_RUN     tool could not run here (missing, wrong version, crashed); the reason is recorded
A FLAGGED check is not a failure by itself: the stamp's findings say what each item was.
Files that text checks did not read (binary, larger than TEXT_LIMIT, symlinks, submodules)
are listed in checks.json under "not_scanned".
"""
import argparse, fnmatch, hashlib, ipaddress, json, os, re, shutil, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
TEXT_LIMIT = 2_000_000  # bytes; larger blobs are scanned by gitleaks only
CHECKER_VERSION = "aien-audit-checks/3"
LOCK_PATH = os.path.join(HERE, "tools.lock.json")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, **kw)


def ver(cmd):
    try:
        r = run(cmd, text=True, timeout=120)
        return ((r.stdout or r.stderr).strip().splitlines() or [""])[0]
    except Exception as e:  # noqa: BLE001
        return "unavailable: " + type(e).__name__


def load_lock(path=LOCK_PATH):
    with open(path, "rb") as fh:
        data = fh.read()
    return json.loads(data), hashlib.sha256(data).hexdigest()


class Ctx:
    def __init__(self, gd, sha, repo, fork_base, tools, root, entries, cats, lock=None):
        self.gd, self.sha, self.repo, self.fork_base, self.tools = gd, sha, repo, fork_base, tools
        self.root, self.entries, self.cats = root, entries, cats
        self.lock = lock if lock is not None else {"tools": {}}
        self.not_scanned = {}  # path -> reason, for files the text checks could not read
        self.extra_paths = []
        self.wt = ""

    def tool(self, name):
        """Return (path, version, reason). path is None when the tool is missing or not the pinned version."""
        p = os.path.join(self.tools, name)
        p = p if os.path.exists(p) else shutil.which(os.path.basename(name))
        if not p:
            return None, "", f"{name} not installed"
        pin = self.lock.get("tools", {}).get(name)
        if not pin:
            return None, "", f"{name} has no pin in tools.lock.json"
        v = ver([p, *pin["version_cmd"]])
        if not re.search(r"(?<![0-9.])%s(?![0-9])" % re.escape(pin["version"]), v):
            return None, v, f"{name} reports {v!r}, tools.lock.json pins {pin['version']}"
        return p, v, ""

    def texts(self, categories=("first_party", "generated", "evidence")):
        for p in self.paths(categories):
            full = os.path.join(self.root, p)
            if os.path.getsize(full) > TEXT_LIMIT:
                self.not_scanned[p] = "larger than %d bytes" % TEXT_LIMIT
                continue
            with open(full, "rb") as fh:
                data = fh.read()
            if b"\0" in data[:8000]:
                self.not_scanned[p] = "binary (NUL byte in first 8000 bytes)"
                continue
            yield p, data.decode("utf-8", "replace")

    def paths(self, categories):
        return [p for p in sorted(self.cats) if self.cats[p][0] in categories]


def result(check, tool, version, command, items, reproducible=True, note="", status=None, payload=None):
    """Summary entry plus the exact bytes to write. output_sha256 always covers those bytes."""
    norm = canonical(items if payload is None else payload)
    if status is None:
        status = "FLAGGED" if items else "PASS"
    return {"check": check, "tool": tool, "version": version, "command": command, "status": status,
            "count": len(items) if isinstance(items, list) else None,
            "output_sha256": hashlib.sha256(norm).hexdigest(), "reproducible": reproducible, "note": note}, norm


def not_run(check, tool, reason, version="", reproducible=True):
    return result(check, tool, version, "", [], status="NOT_RUN", note=reason, reproducible=reproducible)


# C1: secrets over history ----------------------------------------------------------------------
def c1(ctx):
    gl, v, why = ctx.tool("gitleaks")
    if not gl:
        return not_run("C1-secrets", "gitleaks", why, v)
    rng = f"{ctx.fork_base}..{ctx.sha}" if ctx.fork_base else ctx.sha
    with tempfile.TemporaryDirectory() as t:
        rep = os.path.join(t, "r.json")
        cmd = [gl, "git", "--no-banner", "--redact", "--exit-code", "0", "--report-format", "json",
               "--report-path", rep, "--log-opts", rng, ctx.gd]
        r = run(cmd)
        if r.returncode != 0 or not os.path.exists(rep):
            return not_run("C1-secrets", "gitleaks", "gitleaks exit %d: %s" % (r.returncode, r.stderr.decode()[-300:]), v)
        with open(rep) as fh:
            raw = json.load(fh) or []
    items = sorted({(f["RuleID"], f["File"], f["Commit"], f["StartLine"]) for f in raw})
    items = [{"rule": a, "file": b, "commit": c, "line": d} for a, b, c, d in items]
    cmd_s = f"gitleaks git --no-banner --redact --exit-code 0 --report-format json --log-opts {rng} <git-dir>"
    return result("C1-secrets", "gitleaks", v, cmd_s, items,
                  note="history reachable from the commit" + (" since the upstream merge-base" if ctx.fork_base else "")
                  + "; secrets redacted by gitleaks; each hit is triaged in findings")


# C2: license consistency -----------------------------------------------------------------------
LICENSE_SIGS = [
    ("AGPL-3.0", r"GNU AFFERO GENERAL PUBLIC LICENSE"),
    ("LGPL", r"GNU LESSER GENERAL PUBLIC LICENSE"),
    ("GPL", r"GNU GENERAL PUBLIC LICENSE"),
    ("Apache-2.0", r"Apache License,?\s+Version 2\.0"),
    ("MPL-2.0", r"Mozilla Public License,? (version|v\.?) ?2\.0"),
    ("MIT", r"Permission is hereby granted, free of charge"),
    ("BSD", r"Redistribution and use in source and binary forms"),
    ("Unlicense", r"This is free and unencumbered software"),
    ("CC-BY-4.0", r"Creative Commons Attribution 4\.0"),
    ("CC0-1.0", r"CC0 1\.0 Universal"),
    ("BSD-2-Clause-Patent", r"BSD-2-Clause-Patent"),
    ("Community-Spec-1.0", r"Community Specification License 1\.0"),
]
# An SPDX expression: ids joined by AND/OR/WITH (either case), optional parens, ending the line or
# comment. Prose that merely mentions the tag ("... GPL-2.0-only and remain under") does not match.
_SPDX_ID = r"\(*[A-Za-z0-9.+\-]+\)*"
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*(" + _SPDX_ID + r"(?:\s+(?:AND|OR|WITH|and|or|with)\s+"
                     + _SPDX_ID + r")*)\s*(?:\*/|-->|$)", re.M)
CARGO_RE = re.compile(r'^\s*license\s*=\s*"([^"]+)"', re.M)
LICENSE_FILE_RE = re.compile(r"(?i)^((LICEN[SC]E|COPYING|UNLICENSE)([.-].*)?|.+\.LICEN[SC]E)$")


def ident(text):
    """Name the licence a licence file grants: an SPDX expression it declares in its first 1 KB wins;
    otherwise the signature that appears EARLIEST in the text (a GPL text mentions the LGPL further down,
    a dual-licence file names both). A file that opens with its own versioned licence title before the
    first known signature (a custom licence wrapping Apache text) is UNRECOGNIZED, not the wrapped licence."""
    m = SPDX_RE.search(text[:1000])
    if m:
        return m.group(1).strip()
    text = re.sub(r"\s+", " ", text)  # reflowed licence text (license.rst) still matches its signature
    hits = [(mm.start(), name) for name, rx in LICENSE_SIGS for mm in [re.search(rx, text, re.I)] if mm]
    if not hits:
        return "UNRECOGNIZED"
    start, name = min(hits)
    if re.search(r"\bLicen[sc]e,?\s+(v(ersion)?\.?\s*)?\d", text[:start], re.I):
        return "UNRECOGNIZED"
    return name


def families(expr):
    return set(re.findall(r"[A-Za-z0-9.\-+]+", expr)) - {"OR", "AND", "WITH", "or", "and", "with"}


def c2(ctx):
    # Licence files are read from the audited commit itself, not from the scanned file set: in fork-diff mode
    # the upstream LICENSE is unchanged, so it is outside the diff but still governs the tree. A licence file
    # in a subdirectory (adapters/x/LICENSE, om/tka/tailscale.LICENSE) also governs the files below it.
    root_lic, dir_lic = {}, {}
    for _mode, typ, _oid, p in loc.tree_entries(ctx.gd, ctx.sha):
        base = p.rsplit("/", 1)[-1]
        if typ != "blob" or not LICENSE_FILE_RE.match(base):
            continue
        name = ident(loc.git(ctx.gd, "cat-file", "blob", "%s:%s" % (ctx.sha, p)).decode("utf-8", "replace"))
        if "/" not in p:
            if not base.lower().endswith(".license"):
                root_lic[p] = name
        elif name != "UNRECOGNIZED":
            dir_lic.setdefault(p.rsplit("/", 1)[0], set()).update(families(name))
    spdx, manifests = {}, {}
    for p, t in ctx.texts(("first_party",)):
        for m in SPDX_RE.finditer(t[:4000]):
            spdx.setdefault(m.group(1).strip(), []).append(p)
        base = os.path.basename(p)
        if base == "Cargo.toml":
            for m in CARGO_RE.finditer(t):
                manifests.setdefault(m.group(1), []).append(p)
        elif base == "package.json":
            try:
                v = json.loads(t).get("license")
                if isinstance(v, str):
                    manifests.setdefault(v, []).append(p)
            except ValueError:
                pass
        elif base == "pyproject.toml":
            m = re.search(r'^\s*license\s*=\s*(?:\{\s*text\s*=\s*)?"([^"]+)"', t, re.M)
            if m:
                manifests.setdefault(m.group(1), []).append(p)
    declared = set()
    for name in root_lic.values():
        if name != "UNRECOGNIZED":
            declared |= families(name)
    items = []
    if not root_lic:
        items.append({"kind": "no-root-license"})
    for name, f in sorted(root_lic.items()):
        # LICENSE/COPYING itself must be recognized; an extra root file (License-History.txt) only matters
        # when nothing at the root is recognized.
        stem = name.rsplit(".", 1)[0].upper()
        if f == "UNRECOGNIZED" and (stem in ("LICENSE", "LICENCE", "COPYING") or not declared):
            items.append({"kind": "unrecognized-root-license", "file": name})

    def governing(path):
        found = set(declared)
        parts = path.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            found |= dir_lic.get("/".join(parts[:i]), set())
        return found

    def compatible(expr, path):
        toks = families(expr)
        for d in governing(path):
            for tk in toks:
                if tk.upper().startswith(d.upper().split("-")[0]):
                    return True
        return False

    for expr, ps in sorted(spdx.items()):
        bad = sorted(p for p in ps if not compatible(expr, p))
        if bad:
            items.append({"kind": "spdx-differs-from-root", "spdx": expr, "files": len(bad), "examples": bad[:5]})
    for expr, ps in sorted(manifests.items()):
        bad = sorted(p for p in ps if not compatible(expr, p))
        if bad:
            items.append({"kind": "manifest-differs-from-root", "license": expr, "files": bad[:10]})
    summary = {"root": root_lic, "spdx": {k: len(v) for k, v in sorted(spdx.items())},
               "manifests": {k: len(v) for k, v in sorted(manifests.items())},
               "nested": {d: sorted(v) for d, v in sorted(dir_lic.items())}}
    payload = {"items": items, "summary": summary}
    r, norm = result("C2-license", "checks.py", CHECKER_VERSION,
                     "root and nested LICENSE text signatures vs SPDX headers (first 4 KB) vs Cargo.toml/package.json/pyproject license",
                     items, payload=payload,
                     note="heuristic match by license family; mismatches are decisions for the owner, not proof of violation")
    r["summary"] = summary
    return r, norm


# C3: private paths, internal addresses, personal emails ---------------------------------------
PRIV_PATTERNS = {
    "home-path": re.compile(r"/home/[a-z_][a-z0-9_-]{1,31}/"),
    "mac-user-path": re.compile(r"/Users/[A-Za-z][A-Za-z0-9._-]{0,31}/"),
    "ipv4": re.compile(r"(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}
CGNAT = ipaddress.ip_network("100.64.0.0/10")
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
SAFE_EMAIL = re.compile(r"(noreply|no-reply|example\.(com|org|net)|users\.noreply\.github\.com|localhost|\.invalid$|\.test$)", re.I)
ORG_EMAIL = re.compile(r"@aienos\.com$", re.I)


def ip_class(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip in CGNAT:
        return "ip-cgnat-tailnet"
    if any(ip in n for n in RFC1918):
        return "ip-rfc1918"
    return None


def c3(ctx):
    items = []
    for p, t in ctx.texts(("first_party", "generated", "evidence")):
        cat = ctx.cats[p][0]
        for n, line in enumerate(t.split("\n"), 1):
            for kind, rx in PRIV_PATTERNS.items():
                for m in rx.finditer(line):
                    val = m.group(0)
                    if kind == "ipv4":
                        k = ip_class(m.group(1))
                        if not k:
                            continue
                    elif kind == "email":
                        if SAFE_EMAIL.search(val):
                            continue
                        k = "email-org-domain" if ORG_EMAIL.search(val) else "email"
                    else:
                        k = kind
                    if k.startswith(("email", "ip-")):
                        # published stamps must not re-broadcast addresses; the digest is still reproducible
                        val = "sha256:" + hashlib.sha256(val.encode()).hexdigest()[:16]
                    items.append({"kind": k, "file": p, "line": n, "category": cat, "value": val})
    items.sort(key=lambda i: (i["file"], i["line"], i["kind"], i["value"]))
    counts = {}
    for i in items:
        key = i["kind"] + "@" + i["category"]
        counts[key] = counts.get(key, 0) + 1
    r, norm = result("C3-privacy", "checks.py", CHECKER_VERSION,
                     "regex: /home/<user>/, /Users/<user>/, 100.64.0.0/10 and RFC1918 IPv4, non-noreply emails; "
                     "first_party+generated+evidence text files", items,
                     note="presence is not proof of harm (paths in docs/evidence are often intended); each kind is triaged; "
                          "email and IP values are recorded as sha256:<first 16 hex> of the matched text")
    r["counts"] = dict(sorted(counts.items()))
    return r, norm


# C4: internal relative links in Markdown ------------------------------------------------------
MD_LINK = re.compile(r"\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
INLINE_CODE = re.compile(r"`[^`]*`")


def c4(ctx):
    # Targets resolve against every path in the audited commit, not only the scanned set: in fork-diff mode
    # a link from our file may point at an unchanged upstream file.
    tracked = {e[3] for e in loc.tree_entries(ctx.gd, ctx.sha)}
    dirs = set()
    for p in tracked:
        parts = p.split("/")
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    items = []
    for p, t in ctx.texts(("first_party",)):
        if not p.lower().endswith((".md", ".markdown")):
            continue
        in_code = False
        for n, line in enumerate(t.split("\n"), 1):
            if line.lstrip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            # inline code spans are not links (`alloc[T](n)` is call syntax); "[`x`](y)" keeps its target
            for m in MD_LINK.finditer(INLINE_CODE.sub("", line)):
                tgt = m.group(1)
                if re.match(r"^[a-z][a-z0-9+.-]*:", tgt, re.I) or tgt.startswith("#") or tgt.startswith("//"):
                    continue
                path = tgt.split("#", 1)[0].split("?", 1)[0]
                if not path:
                    continue
                from urllib.parse import unquote
                path = unquote(path)
                if path.startswith("/"):
                    res = path.lstrip("/")
                else:
                    res = os.path.normpath(os.path.join(os.path.dirname(p), path)).replace(os.sep, "/")
                res = res.rstrip("/")
                if res.startswith(".."):
                    items.append({"file": p, "line": n, "target": tgt, "reason": "escapes repository"})
                elif res not in tracked and res not in dirs and res != ".":
                    items.append({"file": p, "line": n, "target": tgt, "reason": "not in tree"})
    items.sort(key=lambda i: (i["file"], i["line"], i["target"]))
    return result("C4-internal-links", "checks.py", CHECKER_VERSION,
                  "Markdown relative links resolved against the commit's tree (code fences and inline code skipped)", items,
                  note="external URLs are not checked here (not reproducible)")


# C5: semgrep static analysis -------------------------------------------------------------------
def semgrep_error_type(e):
    t = e.get("type", "")
    # semgrep emits either "Timeout" or ["PartialParsing", [locations...]]
    return str(t[0]) if isinstance(t, list) and t else str(t)


def c5(ctx):
    sg, v, why = ctx.tool("venv/bin/semgrep")
    cfg = os.path.join(ctx.tools, "semgrep-config.yaml")
    if not sg:
        return not_run("C5-semgrep", "semgrep", why, v)
    if not os.path.exists(cfg):
        return not_run("C5-semgrep", "semgrep", "semgrep-config.yaml missing (build it with semgrep_config.py)", v)
    with open(cfg, "rb") as fh:
        cfg_sha = hashlib.sha256(fh.read()).hexdigest()
    want = ctx.lock.get("semgrep_rules", {}).get("config_sha256")
    if cfg_sha != want:
        return not_run("C5-semgrep", "semgrep", f"semgrep-config.yaml sha256 {cfg_sha} != tools.lock.json {want}", v)
    targets = ctx.paths(("first_party",))
    if not targets:
        return result("C5-semgrep", "semgrep", v, "", [], note="no first-party files")
    with tempfile.TemporaryDirectory() as t:
        rep = os.path.join(t, "out.json")
        cmd = [sg, "scan", "--metrics", "off", "--disable-version-check", "--no-git-ignore", "--jobs", "2",
               "--timeout", "30", "--max-target-bytes", str(TEXT_LIMIT), "--config", cfg, "--json", "--output", rep,
               "--quiet"]
        # Scan only first-party files: copy them into a separate tree so vendored code is excluded.
        scan = os.path.join(t, "scan")
        for p in targets:
            dst = os.path.join(scan, p)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copyfile(os.path.join(ctx.root, p), dst)
        r = run(cmd + [scan], cwd=t, env={**os.environ, "SEMGREP_SEND_METRICS": "off"})
        if not os.path.exists(rep):
            return not_run("C5-semgrep", "semgrep", "semgrep exit %d: %s" % (r.returncode, r.stderr.decode()[-300:]), v)
        try:
            with open(rep) as fh:
                out = json.load(fh)
        except ValueError:
            return not_run("C5-semgrep", "semgrep", "semgrep exit %d wrote unparsable JSON" % r.returncode, v)
    items = sorted({(x["check_id"].split(".")[-1], os.path.relpath(x["path"], scan), x["start"]["line"],
                     x["extra"].get("severity", "")) for x in out.get("results", [])})
    items = [{"rule": a, "file": b, "line": c, "severity": d} for a, b, c, d in items]
    errors = sorted({(semgrep_error_type(e), os.path.relpath(e["path"], scan) if e.get("path") else "")
                     for e in out.get("errors", [])})
    errors = [{"type": a, "file": b} for a, b in errors]
    skipped = sorted({(os.path.relpath(s.get("path", scan), scan), str(s.get("reason", "")))
                      for s in (out.get("paths", {}) or {}).get("skipped", []) or []})
    skipped = [{"file": a, "reason": b} for a, b in skipped]
    status = None
    note = "pattern-based; hits are triaged. CodeQL is not part of this checker"
    if errors or skipped or r.returncode not in (0, 1):
        status = "INCOMPLETE"
        note += "; %d error(s) and %d skipped target(s) listed in the output, exit %d" % (len(errors), len(skipped), r.returncode)
    res, norm = result("C5-semgrep", "semgrep", v,
                       "semgrep scan --metrics off --no-git-ignore --jobs 2 --timeout 30 --config semgrep-config.yaml "
                       "(semgrep-rules @ pinned commit, ERROR+WARNING rules for bash/c/python/js/ts/rust/dockerfile/"
                       "github-actions/generic secrets+ci) over first-party files", items, status=status, note=note,
                       payload={"items": items, "errors": errors, "skipped": skipped})
    res["errors"] = len(errors)
    res["skipped_targets"] = len(skipped)
    res["targets"] = len(targets)
    res["config_sha256"] = cfg_sha
    return res, norm


# C6: workflow security ---------------------------------------------------------------------------
def c6(ctx):
    wfs = [p for p in sorted(ctx.cats) if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", p)]
    if not wfs:
        r, n = result("C6-workflows", "zizmor+actionlint", "", "", [], note="no workflows in .github/workflows")
        r["status"] = "PASS"
        r["workflows"] = 0
        return r, n
    items, gaps = [], []
    (zz, vz, wz), (al, va, wa) = ctx.tool("venv/bin/zizmor"), ctx.tool("actionlint")
    wdir = os.path.join(ctx.root, ".github", "workflows")
    if not zz:
        gaps.append(wz)
    else:
        r = run([zz, "--offline", "--no-progress", "--format", "json", "--min-severity", "low", wdir])
        # zizmor: 0 = no findings, 10..14 = findings by severity, anything else = the tool failed
        try:
            if r.returncode != 0 and not 10 <= r.returncode <= 14:
                raise ValueError("exit %d" % r.returncode)
            for f in json.loads(r.stdout or b"[]"):
                loc0 = (f.get("locations") or [{}])[0]
                sym = loc0.get("symbolic", {})
                key = sym.get("key", {})
                lk = key.get("Local", {}) if isinstance(key, dict) else {}
                path = lk.get("verbatim_path") or lk.get("given_path") or ""
                line = (loc0.get("concrete", {}).get("location", {}).get("start_point", {}) or {}).get("row", -1) + 1
                items.append({"tool": "zizmor", "rule": f.get("ident", ""), "severity": f.get("determinations", {}).get("severity", ""),
                              "file": os.path.relpath(path, ctx.root) if path.startswith("/") else path, "line": line})
        except ValueError as e:
            gaps.append("zizmor failed (%s): %s" % (e, r.stderr.decode("utf-8", "replace")[-200:]))
    if not al:
        gaps.append(wa)
    else:
        r = run([al, "-format", "{{json .}}", *[os.path.join(ctx.root, w) for w in wfs]], cwd=ctx.root)
        # actionlint: 0 = clean, 1 = problems found, 2/3 = the tool failed
        try:
            if r.returncode not in (0, 1):
                raise ValueError("exit %d" % r.returncode)
            for e in json.loads(r.stdout or b"[]"):
                items.append({"tool": "actionlint", "rule": e.get("kind", ""), "severity": "",
                              "file": os.path.relpath(e.get("filepath", ""), ctx.root), "line": e.get("line", 0)})
        except ValueError as e:
            gaps.append("actionlint failed (%s): %s" % (e, r.stderr.decode("utf-8", "replace")[-200:]))
    if len(gaps) == 2:
        return not_run("C6-workflows", "zizmor+actionlint", "; ".join(gaps), f"{vz}; {va}")
    items = [dict(t) for t in sorted({tuple(sorted(i.items())) for i in items})]
    items.sort(key=lambda i: (i["tool"], i["file"], i["line"], i["rule"]))
    res, norm = result("C6-workflows", "zizmor+actionlint", f"{vz}; {va}",
                       "zizmor --offline --min-severity low .github/workflows; actionlint <workflows>", items,
                       status="INCOMPLETE" if gaps else None, payload={"items": items, "gaps": gaps},
                       note="zizmor offline mode: no online audits (e.g. known-vulnerable actions)"
                            + ("; " + "; ".join(gaps) if gaps else ""))
    res["workflows"] = len(wfs)
    return res, norm


# C8: claims without a resolvable citation ----------------------------------------------------
CLAIM = re.compile(r"\b(PASS(ED)?|QUALIFIED|VERIFIED|DEPLOYED|PRODUCTION[- ]READY|BATTLE[- ]TESTED|100% )\b")
CITE = re.compile(r"(\]\(|https?://|`[^`]*[/.][^`]*`|\b[0-9a-f]{7,40}\b|#\d+|\b[\w./-]+\.(json|log|md|txt|jsonl|sh|om|rs|c|py)\b|NOT_RUN|PROPOSED)")


def c8(ctx):
    items = []
    for p, t in ctx.texts(("first_party",)):
        if not p.lower().endswith(".md") or p.count("/") > 1:
            continue
        in_code = False
        for n, line in enumerate(t.split("\n"), 1):
            if line.lstrip().startswith("```"):
                in_code = not in_code
                continue
            if in_code or not CLAIM.search(line):
                continue
            if not CITE.search(line):
                items.append({"file": p, "line": n, "text": line.strip()[:160]})
    return result("C8-uncited-claims", "checks.py", CHECKER_VERSION,
                  "top-level and one-deep Markdown lines containing PASS/QUALIFIED/VERIFIED/DEPLOYED/PRODUCTION-READY "
                  "with no link, path, commit sha or issue reference on the same line", items,
                  note="heuristic: a hit means the line itself cites nothing, not that the claim is false")


# C9: crumb structure -----------------------------------------------------------------------------
def c9(ctx):
    crumbs = [p for p in ctx.cats if os.path.basename(p) == ".crumb"]
    if not crumbs:
        return result("C9-crumb", "crumb", "", "", [], status="PASS", note="no .crumb files")
    pin = ctx.lock.get("crumb", {})
    tool = "crumb (%s@%s %s)" % (pin.get("repository", "?"), pin.get("commit", "?"), pin.get("source", "?"))
    if not ctx.wt:
        return not_run("C9-crumb", tool, "no worktree given")
    wt_head = run(["git", "-C", ctx.wt, "rev-parse", "HEAD"]).stdout.decode().strip()
    if wt_head != ctx.sha or run(["git", "-C", ctx.wt, "status", "--porcelain"]).stdout.strip():
        return not_run("C9-crumb", tool, "worktree is not a clean checkout of the audited commit (HEAD %s)" % wt_head[:12])
    cr, src = os.path.join(ctx.tools, "crumb-arch"), os.path.join(ctx.tools, "crumb.c")
    if not (os.path.exists(cr) and os.path.exists(src)):
        return not_run("C9-crumb", tool, "crumb-arch binary or its crumb.c source missing from the tools directory")
    with open(src, "rb") as fh:
        src_sha = hashlib.sha256(fh.read()).hexdigest()
    if src_sha != pin.get("source_sha256"):
        return not_run("C9-crumb", tool, f"crumb.c sha256 {src_sha} != tools.lock.json {pin.get('source_sha256')}")
    r = run([cr, "verify", ctx.wt], cwd=ctx.wt)
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    out = out.replace(ctx.wt, "<worktree>")
    items = [] if r.returncode == 0 else [{"exit": r.returncode, "output": out.strip()[-2000:]}]
    res, norm = result("C9-crumb", tool, "source sha256 " + src_sha,
                       "crumb verify <worktree at commit>", items,
                       note="RFC-0003: committed crumb data equals what compile would write")
    res["crumb_files"] = len(crumbs)
    return res, norm


# C11: dependency advisories (snapshot) ----------------------------------------------------------
def c11(ctx):
    osv, v, why = ctx.tool("osv-scanner")
    if not osv:
        return not_run("C11-dep-advisories", "osv-scanner", why, v, reproducible=False)
    with tempfile.TemporaryDirectory() as t:
        scan = os.path.join(t, "scan")
        n = 0
        for p in ctx.paths(("first_party", "generated")):
            if os.path.basename(p) in LOCKFILES:
                dst = os.path.join(scan, p)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(os.path.join(ctx.root, p), dst)
                n += 1
        if not n:
            return result("C11-dep-advisories", "osv-scanner", v, "", [], reproducible=False, note="no lockfiles")
        r = run([osv, "scan", "source", "-r", "--format", "json", scan])
        # osv-scanner: 0 = no vulnerabilities, 1 = vulnerabilities found, 128 = no packages found, other = error
        if r.returncode not in (0, 1):
            why = "no packages parsed from %d lockfile(s)" % n if r.returncode == 128 else "osv-scanner failed"
            return not_run("C11-dep-advisories", "osv-scanner",
                           "%s (exit %d): %s" % (why, r.returncode, r.stderr.decode("utf-8", "replace")[-300:]), v,
                           reproducible=False)
        try:
            out = json.loads(r.stdout or b"")
        except ValueError:
            return not_run("C11-dep-advisories", "osv-scanner", "exit %d with unparsable JSON" % r.returncode, v,
                           reproducible=False)
    items = []
    for res in out.get("results", []) or []:
        src = os.path.relpath(res["source"]["path"], scan)
        for pk in res.get("packages", []):
            for vv in pk.get("vulnerabilities", []):
                items.append({"lockfile": src, "package": pk["package"]["name"], "version": pk["package"].get("version", ""),
                              "id": vv["id"]})
    items = sorted(items, key=lambda i: (i["lockfile"], i["package"], i["version"], i["id"]))
    if r.returncode == 1 and not items:
        return not_run("C11-dep-advisories", "osv-scanner", "exit 1 (vulnerabilities) but none parsed from JSON", v,
                       reproducible=False)
    res, norm = result("C11-dep-advisories", "osv-scanner", v,
                       "osv-scanner scan source -r --format json <lockfiles>", items, reproducible=False,
                       note=f"{n} lockfile(s); OSV database queried online at run time, so results are a dated snapshot")
    res["lockfiles"] = n
    return res, norm


LOCKFILES = ("Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock",
             "go.sum", "requirements.txt", "Gemfile.lock", "composer.lock")


CHECKS = {"C1": c1, "C2": c2, "C3": c3, "C4": c4, "C5": c5, "C6": c6, "C8": c8, "C9": c9, "C11": c11}
CHECK_NAMES = {"C1": "C1-secrets", "C2": "C2-license", "C3": "C3-privacy", "C4": "C4-internal-links", "C5": "C5-semgrep",
               "C6": "C6-workflows", "C8": "C8-uncited-claims", "C9": "C9-crumb", "C11": "C11-dep-advisories"}


def checker_sha256():
    h = hashlib.sha256()
    for name in ("checks.py", "loc.py"):
        with open(os.path.join(HERE, name), "rb") as fh:
            h.update(name.encode() + b"\0" + hashlib.sha256(fh.read()).hexdigest().encode() + b"\n")
    return h.hexdigest()


def run_all(gd, sha, repo, out, fork_base="", tools=HERE, worktree="", only="", lock_path=LOCK_PATH):
    sha = loc.git(gd, "rev-parse", sha + "^{commit}").decode().strip()
    if fork_base:
        fork_base = loc.git(gd, "rev-parse", fork_base + "^{commit}").decode().strip()
    lock, lock_sha = load_lock(lock_path)
    extra = []
    cj = os.path.join(HERE, "classify.json")
    if os.path.exists(cj):
        with open(cj) as fh:
            extra = json.load(fh).get(repo, [])
    entries, not_scanned = [], {}
    for mode, typ, oid, path in loc.tree_entries(gd, sha):
        if typ == "blob" and mode != "120000":
            entries.append((mode, typ, oid, path))
        else:
            not_scanned[path] = "submodule (gitlink)" if typ == "commit" else "symlink"
    if fork_base:
        diff = loc.git(gd, "diff", "--no-renames", "-z", "--name-only", "--diff-filter=AM", fork_base, sha).split(b"\0")
        keep = {d.decode("utf-8", "surrogateescape") for d in diff if d}
        entries = [e for e in entries if e[3] in keep]
        not_scanned = {p: r for p, r in not_scanned.items() if p in keep}
    os.makedirs(out, exist_ok=True)
    at = loc.attrs(gd, sha, [e[3] for e in entries])
    with tempfile.TemporaryDirectory(prefix="aien-checks-") as root:
        heads = loc.materialize(gd, entries, root)
        cats = {p: loc.classify(p, heads[p][0], at.get(p, set()), extra) for p in heads}
        ctx = Ctx(gd, sha, repo, fork_base, tools, root, entries, cats, lock)
        ctx.extra_paths = list(not_scanned)
        ctx.wt = worktree
        summary = []
        for cid, fn in CHECKS.items():
            if only and cid not in only.split(","):
                continue
            try:
                r, norm = fn(ctx)
            except Exception as e:  # noqa: BLE001 - a crashed check is NOT_RUN, never a silent gap
                r, norm = not_run(CHECK_NAMES[cid], "checks.py", "checker crashed: %s: %s" % (type(e).__name__, str(e)[:300]))
            with open(os.path.join(out, r["check"] + ".json"), "wb") as fh:
                fh.write(norm)
            summary.append(r)
            print(f"{repo} {r['check']} {r['status']} {r['count']}", file=sys.stderr)
        not_scanned.update(ctx.not_scanned)
    doc = {"schema": "aien-audit-checks/2", "repository": repo, "commit": sha,
           "mode": "fork-diff" if fork_base else "full-tree", "fork_base": fork_base or None,
           "checker": {"version": CHECKER_VERSION, "sha256": checker_sha256()}, "tools_lock_sha256": lock_sha,
           "files": len(entries), "checks": summary,
           "not_scanned": [{"path": p, "reason": not_scanned[p]} for p in sorted(not_scanned)]}
    data = canonical(doc)
    with open(os.path.join(out, "checks.json"), "wb") as fh:
        fh.write(data)
    return doc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gitdir")
    ap.add_argument("sha")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--fork-base", default="")
    ap.add_argument("--tools", default=os.environ.get("AUDIT_TOOLS", HERE))
    ap.add_argument("--worktree", default="", help="checkout at <sha> for tools that need a work tree (crumb)")
    ap.add_argument("--only", default="")
    ap.add_argument("--lock", default=LOCK_PATH)
    a = ap.parse_args()
    run_all(a.gitdir, a.sha, a.repo, a.out, a.fork_base, a.tools, a.worktree, a.only, a.lock)


if __name__ == "__main__":
    main()
