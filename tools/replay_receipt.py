#!/usr/bin/env python3
"""Admit and replay receipts listed in index/receipt_index.json (DRA-167).

`admit` computes one index entry live from pinned commits. `replay` fetches an
indexed entry again by its pinned commits, checks the shelf bytes against the
recorded SHA-256, recomputes every other field (correction precedence, bundle
signature and trust anchor, source provenance, issue_or_gate) and compares it
with the index. Both also read the current HEAD of the shelf repository and
refuse an entry when the correction file there differs from the one at the
pinned commit, and replay refuses any entry or index field it does not know.
The last line printed is the verdict. Rules: docs/receipt-index.md.

Exit codes for one entry: 0 PASS, 1 FAIL (an authenticated FAIL verdict),
2 NOT_RUN (an input could not be reached, or a usage error), 3 REJECTED (bytes,
signature, binding, correction binding, a newer correction at the shelf HEAD,
an unknown field or index drift), 4 REFUSED (admission refused by a shelf
correction or by the source-provenance check).
`replay --all` exits 0 only when every entry reproduces exactly as indexed.

Needs Python 3, Git and OpenSSL 3 (Ed25519). Repository convention: the only
other tooling in this repository (audit/tools) is Python with unittest.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile

INDEX_SCHEMA = "aien.receipt-index.v2"
BUNDLE_SCHEMA = "aien-verification-bundle/1"
CORRECTION_SCHEMA = "aien.omega-evidence.receipt-correction.v1"
SHELF_OWNER = "aien-dev"
# Each kind lives on exactly one shelf; the index cannot point a kind elsewhere.
SHELF_REPOS = {"signed-bundle": "aien-dev/aien-receipts", "omega-qualification-receipt": "aien-dev/omega-evidence"}
KINDS = tuple(SHELF_REPOS)
# Every field an index may carry. Replay rejects anything else (UNKNOWN_FIELD / SCHEMA).
INDEX_FIELDS = {"schema", "index_version", "issue", "generated_by", "independence", "admission_check",
                "precedence", "exit_codes", "scope", "excluded", "generated_utc", "entries"}
_ENTRY_COMMON = {"id", "kind", "issue_or_gate", "shelf", "source", "correction", "historical_verdict",
                 "effective_verdict", "effective_basis", "replay"}
ENTRY_FIELDS = {"signed-bundle": _ENTRY_COMMON | {"trust_anchor", "signature", "gates"},
                "omega-qualification-receipt": _ENTRY_COMMON}
# Effective basis of a signed bundle. Taken on trust: see docs/receipt-index.md, "Values taken on trust".
BUNDLE_BASIS = "authenticated bundle verdict (this shelf has no correction records)"
UNVERIFIED_ISSUE_BASIS = "UNVERIFIED: not derivable from the receipt; text supplied at admission"
EXIT = {"PASS": 0, "FAIL": 1, "NOT_RUN": 2, "REJECTED": 3, "REFUSED": 4}
# DER SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key.
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")
# Bundle vocabulary of aien-sovereign-core@c26f4d7a tools/aien-test/src/bundle.rs.
STATUSES = ("run", "cached", "not_run", "blocked")
VERDICTS = ("PASS", "FAIL", "NOT_RUN", "BLOCKED_HARDWARE", "BLOCKED_OPERATOR", "MISSING_IMPLEMENTATION")
EXACTNESS = ("EXACT", "BOUNDED", "APPROXIMATE", "ADVISORY")
RECEIPT_ID_SCHEMES = ("sha256-canonical-json", "aien-proof-blake3")
# Omega receipts name their implementation commit in one of these fields, first match wins.
SOURCE_COMMIT_FIELDS = ("qualified_implementation_commit", "git_commit")
ADMITTED_HISTORICAL_STATUS = "QUALIFIED / PASS"
DEFAULT_INDEX = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "index", "receipt_index.json")


class Rejected(Exception):
    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code = code


class NotRun(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def is_hex(s, n):
    return isinstance(s, str) and len(s) == n and all(c in "0123456789abcdef" for c in s)


# ------------------------------------------------------------- canonical JSON
# Port of evidence::canonical (aien-sovereign-core@c26f4d7a): sorted keys by
# UTF-8 bytes, compact, integers only, minimal escapes.

def _canon_str(s, out):
    out.append('"')
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')


def _canon_val(v, out):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if not -(1 << 63) <= v < (1 << 64):
            raise ValueError(f"integer out of range: {v}")
        out.append(str(v))
    elif isinstance(v, float):
        raise ValueError(f"floating point not allowed: {v!r}")
    elif isinstance(v, str):
        _canon_str(v, out)
    elif isinstance(v, list):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _canon_val(x, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        for i, k in enumerate(sorted(v, key=lambda k: k.encode("utf-8"))):
            if i:
                out.append(",")
            _canon_str(k, out)
            out.append(":")
            _canon_val(v[k], out)
        out.append("}")
    else:
        raise ValueError(f"not a JSON value: {type(v).__name__}")


def canonical(v):
    out = []
    _canon_val(v, out)
    return "".join(out).encode("utf-8")


def parse_json(raw, what):
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"duplicate key {k!r}")
            d[k] = v
        return d

    def no_constant(name):
        raise ValueError(f"non-JSON constant {name}")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes, parse_constant=no_constant)
    except (UnicodeDecodeError, ValueError) as e:
        raise Rejected("SCHEMA", f"{what} is not valid JSON: {e}")


# ------------------------------------------------------------- git fetching

class Git:
    """Blobless, shallow fetches of exact commits into a local cache."""

    def __init__(self, cache, remote_base):
        self.cache = cache
        self.base = remote_base.rstrip("/") + "/"
        self.heads = {}  # repository -> HEAD commit, read once per run by ls-remote

    def _git(self, d, *args):
        try:
            return subprocess.run(["git", "-C", d, *args], capture_output=True)
        except FileNotFoundError:
            raise NotRun("git is not installed")

    def _repo(self, repository):
        d = os.path.join(self.cache, repository.replace("/", "__") + ".git")
        if not os.path.isdir(d):
            os.makedirs(d)
            for args in (("init", "-q", "--bare"),
                         ("remote", "add", "origin", self.base + repository),
                         ("config", "remote.origin.promisor", "true"),
                         ("config", "remote.origin.partialclonefilter", "blob:none")):
                if self._git(d, *args).returncode:
                    raise NotRun(f"cannot initialise cache {d}")
        if repository not in self.heads:
            # A reused cache must still talk to the remote named on this run.
            if self._git(d, "remote", "set-url", "origin", self.base + repository).returncode:
                raise NotRun(f"cannot configure cache {d}")
            r = self._git(d, "ls-remote", "origin", "HEAD")
            if r.returncode:
                raise NotRun(f"cannot reach {self.base + repository}: {_last(r.stderr)}")
            head = r.stdout.decode().split("\t", 1)[0].strip()
            if not is_hex(head, 40):
                raise NotRun(f"{self.base + repository} reports no HEAD commit")
            self.heads[repository] = head
        return d

    def head(self, repository):
        """The commit the remote's HEAD names at the moment this run first reached it."""
        self._repo(repository)
        return self.heads[repository]

    def _present(self, d, commit, depth):
        if self._git(d, "cat-file", "-e", commit + "^{commit}").returncode:
            return False
        return depth == 1 or self._git(d, "rev-parse", "--verify", "-q", commit + "^1^{commit}").returncode == 0

    def has_commit(self, repository, commit, depth=1):
        """True if the commit exists upstream; False only on an explicit 'not our ref'."""
        if not is_hex(commit, 40):
            return False
        d = self._repo(repository)
        if self._present(d, commit, depth):
            return True
        r = self._git(d, "fetch", "-q", f"--depth={depth}", "--filter=blob:none", "origin", commit)
        if r.returncode == 0:
            return self._git(d, "cat-file", "-e", commit + "^{commit}").returncode == 0
        if b"not our ref" in r.stderr or b"couldn't find remote ref" in r.stderr:
            return False
        raise NotRun(f"cannot fetch {repository}@{commit}: {_last(r.stderr)}")

    def read(self, repository, commit, path):
        """Bytes of path at commit, or None when the path is absent there."""
        if not self.has_commit(repository, commit):
            raise Rejected("COMMIT_ABSENT", f"{repository}@{commit} does not exist upstream")
        d = self._repo(repository)
        tree = self._git(d, "ls-tree", "--name-only", commit, "--", path)
        if tree.returncode:
            raise NotRun(f"cannot list {repository}@{commit}: {_last(tree.stderr)}")
        if tree.stdout.decode().strip() != path:
            return None
        blob = self._git(d, "cat-file", "blob", f"{commit}:{path}")
        if blob.returncode:
            raise NotRun(f"cannot fetch {repository}@{commit}:{path}: {_last(blob.stderr)}")
        return blob.stdout

    def first_parent(self, repository, commit):
        if not self.has_commit(repository, commit, depth=2):
            raise Rejected("COMMIT_ABSENT", f"{repository}@{commit} does not exist upstream")
        r = self._git(self._repo(repository), "rev-parse", "--verify", "-q", commit + "^1")
        return r.stdout.decode().strip() if r.returncode == 0 else None


def _last(stderr):
    lines = stderr.decode(errors="replace").strip().splitlines()
    return lines[-1] if lines else "no diagnostic"


# ------------------------------------------------------------- signed bundles

def ed25519_verify(pubkey_hex, sig_hex, message):
    with tempfile.TemporaryDirectory() as t:
        paths = {n: os.path.join(t, n) for n in ("pub.der", "sig.bin", "msg.bin")}
        for name, data in (("pub.der", SPKI_ED25519 + bytes.fromhex(pubkey_hex)),
                           ("sig.bin", bytes.fromhex(sig_hex)), ("msg.bin", message)):
            with open(paths[name], "wb") as f:
                f.write(data)
        try:
            r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                                "-inkey", paths["pub.der"], "-rawin", "-in", paths["msg.bin"],
                                "-sigfile", paths["sig.bin"]], capture_output=True)
        except FileNotFoundError:
            raise NotRun("openssl is not installed")
    if r.returncode == 0 and b"Signature Verified Successfully" in r.stdout:
        return True
    if r.returncode == 1 and b"Signature Verification Failure" in r.stdout:
        return False
    raise NotRun(f"openssl could not run the Ed25519 check: {_last(r.stderr)}")


def _schema(cond, detail):
    if not cond:
        raise Rejected("SCHEMA", detail)


def validate_bundle(b):
    """Shape check of bundle.rs validate(); returns [(gate, required, status, verdict)]."""
    _schema(isinstance(b, dict), "bundle must be an object")
    _schema(b.get("schema") == BUNDLE_SCHEMA, f"schema must be {BUNDLE_SCHEMA}")
    _schema(isinstance(b.get("repository"), str), "repository must be a string")
    for k, n in (("commit", 40), ("tree_digest", 64), ("graph_digest", 64)):
        _schema(is_hex(b.get(k), n), f"{k} must be {n} lower-case hex characters")
    _schema(b.get("receipt_id_scheme") in RECEIPT_ID_SCHEMES, "receipt_id_scheme is not allowed")
    _schema(b.get("verdict") in ("PASS", "FAIL", "NOT_RUN"), "verdict is not allowed")
    for k in ("started_utc", "finished_utc"):
        _schema(isinstance(b.get(k), str), f"{k} must be a string")
    ex = b.get("executor")
    _schema(isinstance(ex, dict) and is_hex(ex.get("id"), 64) and isinstance(ex.get("class"), str)
            and is_hex(ex.get("machine_digest"), 64), "executor is malformed")
    checks = b.get("checks")
    _schema(isinstance(checks, list), "checks must be an array")
    entries = []
    for i, c in enumerate(checks):
        _schema(isinstance(c, dict), f"checks[{i}] must be an object")
        gate = c.get("gate")
        _schema(isinstance(gate, str), f"checks[{i}].gate must be a string")
        _schema(is_hex(c.get("check_id"), 64), f"checks[{i}].check_id malformed")
        _schema(c.get("exactness") in EXACTNESS, f"checks[{i}].exactness not allowed")
        _schema(isinstance(c.get("required"), bool), f"checks[{i}].required must be a bool")
        _schema(not (c["required"] and c["exactness"] == "ADVISORY"), f"checks[{i}] ADVISORY cannot be required")
        _schema(c.get("status") in STATUSES, f"checks[{i}].status not allowed")
        _schema(c.get("verdict") in VERDICTS, f"checks[{i}].verdict not allowed")
        _schema(isinstance(c.get("backend"), str), f"checks[{i}].backend must be a string")
        if c["status"] == "run":
            _schema(is_hex(c.get("receipt"), 64), f"checks[{i}].receipt malformed")
        elif c["status"] == "cached":
            r = c.get("resolution")
            _schema(isinstance(r, dict) and is_hex(r.get("resolved_from"), 64), f"checks[{i}].resolution malformed")
        else:
            _schema(c["verdict"] != "PASS", f"checks[{i}] status {c['status']} cannot carry PASS")
        entries.append((gate, c["required"], c["status"], c["verdict"]))
    gates = [e[0] for e in entries]
    _schema(len(gates) == len(set(gates)), "checks[] lists a gate twice")
    return entries


def compute_verdict(entries):
    required = [e for e in entries if e[1]]
    if any(e[3] == "FAIL" for e in required):
        return "FAIL"
    if all(e[2] in ("run", "cached") and e[3] == "PASS" for e in required):
        return "PASS"
    return "NOT_RUN"


def evaluate_bundle(git, shelf, raw, craw):
    parts = shelf["path"].split("/")
    if len(parts) != 3 or parts[2] != "bundle.json" or not is_hex(parts[1], 40):
        raise Rejected("PATH_BINDING", f"{shelf['path']} is not <repo>/<sha>/bundle.json")
    if craw is not None:
        # BUNDLE_BASIS asserts that this shelf has no correction records; refuse rather than ignore one.
        raise Rejected("CORRECTION_UNSUPPORTED", f"{correction_path(shelf['path'])} exists; bundle corrections"
                       " have no admission rule yet")
    source = {"repository": f"{SHELF_OWNER}/{parts[0]}", "commit": parts[1]}
    b = parse_json(raw, shelf["path"])
    entries = validate_bundle(b)
    sig = b.get("signature")
    _schema(isinstance(sig, dict) and sig.get("alg") == "ed25519", "signature.alg must be ed25519")
    _schema(is_hex(sig.get("pubkey"), 64) and is_hex(sig.get("sig"), 128), "signature members malformed")
    base = git.first_parent(source["repository"], source["commit"])
    if base is None:
        raise Rejected("NO_TRUST_ANCHOR", f"{source['commit']} has no parent to read .aien/ from")
    pub = git.read(source["repository"], base, ".aien/verify.pub")
    always = git.read(source["repository"], base, ".aien/always")
    if pub is None or always is None:
        raise Rejected("NO_TRUST_ANCHOR", f"{source['repository']}@{base} lacks .aien/verify.pub or .aien/always")
    pub = pub.decode().strip()
    _schema(is_hex(pub, 64), ".aien/verify.pub must be 64 hex characters")
    required = [ln.strip() for ln in always.decode().splitlines() if ln.strip() and not ln.startswith("#")]
    # verify() order in bundle.rs: key known, signature, repository, commit, executor, required, verdict.
    if sig["pubkey"] != pub:
        raise Rejected("UNKNOWN_KEY", "bundle key is not the base-branch .aien/verify.pub")
    try:
        message = canonical({k: v for k, v in b.items() if k != "signature"})
    except ValueError as e:
        raise Rejected("SCHEMA", f"not canonical-encodable: {e}")
    if not ed25519_verify(pub, sig["sig"], message):
        raise Rejected("BAD_SIGNATURE", "signature does not verify over the canonical bytes")
    if b["repository"] != "github.com/" + source["repository"]:
        raise Rejected("REPOSITORY_MISMATCH", f"bundle {b['repository']}, shelf path {source['repository']}")
    if b["commit"] != source["commit"]:
        raise Rejected("COMMIT_MISMATCH", f"bundle {b['commit']}, shelf path {source['commit']}")
    if b["executor"]["id"] != sha256(bytes.fromhex(pub)):
        raise Rejected("UNKNOWN_EXECUTOR", "executor.id is not sha256(verify.pub)")
    for g in required:
        found = [e for e in entries if e[0] == g]
        if not found:
            raise Rejected("MISSING_REQUIRED_CHECK", g)
        if not found[0][1]:
            raise Rejected("SCHEMA", f"{g} is required by the gate but marked optional in the bundle")
    computed = compute_verdict(entries)
    if computed != b["verdict"]:
        raise Rejected("VERDICT_INCONSISTENT", f"declared {b['verdict']}, computed {computed}")
    gates = [e[0] for e in entries if e[1]]
    return {
        "issue_or_gate": {"value": f"{source['repository']} required gates: {', '.join(gates) or 'none'}",
                          "basis": "bundle repository and the gate of every required check", "verified": True},
        "source": source,
        "trust_anchor": {"repository": source["repository"], "commit": base,
                         "rule": "first parent of the source commit", "verify_pub": pub, "always": required},
        "signature": "VERIFIED (OpenSSL Ed25519 over canonical bytes without the signature member)",
        "gates": [{k: c[k] for k in ("gate", "backend", "exactness", "required", "status", "verdict")}
                  for c in b["checks"]],
        "correction": None,
        "historical_verdict": b["verdict"],
        "effective_verdict": b["verdict"],
        "effective_basis": BUNDLE_BASIS,
    }


# ------------------------------------------------------------- omega receipts

def omega_issue_or_gate(d):
    """Issue or gate named by the receipt itself, or None when the receipt names none."""
    milestone, contract = d.get("milestone"), d.get("contract_id")
    if not isinstance(milestone, str) or not milestone.strip():
        return None
    if isinstance(contract, str) and contract.strip():
        return {"value": f"Omega {milestone} qualification ({contract})",
                "basis": "receipt fields milestone and contract_id", "verified": True}
    return {"value": f"Omega {milestone} qualification", "basis": "receipt field milestone", "verified": True}


def evaluate_omega(git, shelf, raw, source_repository, craw):
    d = parse_json(raw, shelf["path"])
    _schema(isinstance(d, dict), "receipt must be an object")
    # The receipts do not name their source repository; it is taken from the index (docs, "Values taken on trust").
    _schema(isinstance(source_repository, str) and source_repository.startswith(SHELF_OWNER + "/")
            and source_repository.count("/") == 1, f"source.repository must be {SHELF_OWNER}/<name>")
    historical = d.get("status")
    if historical != ADMITTED_HISTORICAL_STATUS:
        raise Rejected("UNSUPPORTED_STATUS", f"status {historical!r} is not {ADMITTED_HISTORICAL_STATUS!r}")
    correction = None
    if craw is not None:
        cpath = correction_path(shelf["path"])
        c = parse_json(craw, cpath)
        _schema(isinstance(c, dict) and c.get("schema") == CORRECTION_SCHEMA, f"{cpath} schema")
        corr = c.get("corrects") or {}
        if (corr.get("repository"), corr.get("path"), corr.get("sha256")) != (
                shelf["repository"], shelf["path"], sha256(raw)):
            raise Rejected("CORRECTION_UNBOUND", f"{cpath} does not name these receipt bytes")
        disp = c.get("disposition") or {}
        _schema(isinstance(disp.get("supersedes_historical_status_for_admission"), bool)
                and isinstance(disp.get("qualification_claim"), str), f"{cpath} disposition malformed")
        correction = {"path": cpath, "sha256": sha256(craw), "correction_id": c.get("correction_id"),
                      "recorded_on": c.get("recorded_on"),
                      "supersedes_historical_status_for_admission":
                          disp["supersedes_historical_status_for_admission"],
                      "qualification_claim": disp["qualification_claim"]}
    field = next((f for f in SOURCE_COMMIT_FIELDS if is_hex(d.get(f), 40)), None)
    commit = d[field] if field else None
    resolves = bool(commit) and git.has_commit(source_repository, commit)
    artifacts = []
    arts = d.get("artifacts") if isinstance(d.get("artifacts"), dict) else {}
    for path in sorted(arts):
        v = arts[path]
        digest = v.get("sha256") if isinstance(v, dict) else None
        if not is_hex(digest, 64):
            result = "no-digest"
        elif path.startswith("build/"):
            result = "not-recoverable (build output)"
        elif not resolves:
            result = "commit-unresolved"
        else:
            src = git.read(source_repository, commit, path)
            result = "absent" if src is None else ("match" if sha256(src) == digest else "mismatch")
        artifacts.append({"path": path, "sha256": digest, "at_source_commit": result})
    source_ok = (resolves and any(a["at_source_commit"] == "match" for a in artifacts)
                 and all(a["at_source_commit"] in ("match", "not-recoverable (build output)", "no-digest")
                         for a in artifacts))
    rc = d.get("receipt_commit")
    receipt_commit = {"value": rc, "resolves": git.has_commit(source_repository, rc) if is_hex(rc, 40) else None}
    if correction and correction["supersedes_historical_status_for_admission"]:
        effective, basis = correction["qualification_claim"], f"shelf correction {correction['correction_id']}"
    elif not source_ok:
        effective, basis = "REFUSED_SOURCE_PROVENANCE", "index source check (no superseding shelf correction)"
    else:
        effective, basis = "PASS", "historical status; named source commit resolves and source digests match"
    return {
        "issue_or_gate": omega_issue_or_gate(d),
        "source": {"repository": source_repository, "commit_field": field, "commit": commit,
                   "commit_resolves": resolves, "receipt_commit": receipt_commit, "artifacts": artifacts,
                   "source_check": "PASS" if source_ok else "FAIL"},
        "correction": correction,
        "historical_verdict": historical,
        "effective_verdict": effective,
        "effective_basis": basis,
    }


# ------------------------------------------------------------- admit / replay

def correction_path(path):
    return path[:-len(".json")] + ".correction.json"


def evaluate(git, kind, shelf_loc, source_repository, raw, stated_issue=None):
    """Recompute an entry. stated_issue is used only when the receipt names no issue or gate."""
    if kind not in KINDS:
        raise Rejected("SCHEMA", f"unknown kind {kind!r}")
    repo, commit, path = shelf_loc["repository"], shelf_loc["commit"], shelf_loc["path"]
    if repo != SHELF_REPOS[kind]:
        raise Rejected("SHELF_REPOSITORY", f"{kind} receipts live in {SHELF_REPOS[kind]}, not {repo}")
    _schema(isinstance(path, str) and path.endswith(".json"), "shelf.path must name a .json file")
    shelf = {"repository": repo, "commit": commit, "path": path, "sha256": sha256(raw), "bytes": len(raw)}
    # A correction may land after the pinned commit. The one at the shelf HEAD must be the one pinned.
    cpath = correction_path(path)
    craw = git.read(repo, commit, cpath)
    head = git.head(repo)
    at_head = craw if head == commit else git.read(repo, head, cpath)
    if at_head != craw:
        state = "is absent" if at_head is None else f"has sha256 {sha256(at_head)}"
        pinned = "absent" if craw is None else f"sha256 {sha256(craw)}"
        raise Rejected("STALE_CORRECTION", f"{cpath} at {repo} HEAD {head} {state}; at the indexed commit "
                       f"{commit} it is {pinned}. Re-admit the entry at the HEAD")
    if kind == "signed-bundle":
        out = evaluate_bundle(git, shelf, raw, craw)
    else:
        out = evaluate_omega(git, shelf, raw, source_repository, craw)
    if out["issue_or_gate"] is None:
        if not isinstance(stated_issue, str) or not stated_issue.strip():
            raise Rejected("SCHEMA", "the receipt names no issue or gate; supply one (it is recorded UNVERIFIED)")
        out["issue_or_gate"] = {"value": stated_issue, "basis": UNVERIFIED_ISSUE_BASIS, "verified": False}
    return {"kind": kind, "shelf": shelf, **out}


def fetch_shelf(git, shelf_loc):
    raw = git.read(shelf_loc["repository"], shelf_loc["commit"], shelf_loc["path"])
    if raw is None:
        raise Rejected("SHELF_PATH_ABSENT", f"{shelf_loc['path']} absent at {shelf_loc['repository']}@{shelf_loc['commit']}")
    return raw


def exit_for(effective):
    if effective in ("PASS", "FAIL", "NOT_RUN"):
        return EXIT[effective]
    if effective.startswith("REFUSED"):
        return EXIT["REFUSED"]
    return EXIT["NOT_RUN"]


def replay_command(eid):
    return f"python3 tools/replay_receipt.py replay {eid}"


def replay_entry(git, entry, override=None):
    """Returns (rc, last line, reproduced). Prints the evidence lines before it."""
    eid = entry.get("id", "?")
    try:
        kind = entry.get("kind")
        if kind not in KINDS:
            raise Rejected("SCHEMA", f"unknown kind {kind!r}")
        unknown = sorted(set(entry) - ENTRY_FIELDS[kind])
        if unknown:
            raise Rejected("UNKNOWN_FIELD", "the index entry carries fields this tool does not check: "
                           + ", ".join(unknown))
        if not isinstance(eid, str) or not eid or ":" in eid:
            raise Rejected("SCHEMA", "id must be a non-empty string without ':'")
        if entry.get("replay") != replay_command(eid):
            raise Rejected("INDEX_DRIFT", "recomputed fields differ from the index: replay")
        shelf = entry.get("shelf")
        _schema(isinstance(shelf, dict) and all(isinstance(shelf.get(k), str) for k in
                                                 ("repository", "commit", "path", "sha256")), "shelf malformed")
        print(f"entry: {eid} ({kind})")
        if override is not None:
            with open(override, "rb") as f:
                raw = f.read()
            print(f"shelf: local override {override} (not fetched)")
        else:
            raw = fetch_shelf(git, shelf)
            print(f"shelf: fetched {shelf['repository']}@{shelf['commit']}:{shelf['path']}")
        got = sha256(raw)
        print(f"digest: sha256={got} expected={shelf['sha256']}")
        if got != shelf["sha256"]:
            raise Rejected("DIGEST_MISMATCH", f"sha256 {got} != indexed {shelf['sha256']}")
        issue = entry.get("issue_or_gate")
        computed = evaluate(git, kind, shelf, (entry.get("source") or {}).get("repository"), raw,
                            issue.get("value") if isinstance(issue, dict) else None)
        drift = sorted(k for k in computed if computed[k] != entry.get(k))
        if drift:
            raise Rejected("INDEX_DRIFT", "recomputed fields differ from the index: " + ", ".join(drift))
        i = computed["issue_or_gate"]
        if i["verified"]:
            print(f"issue_or_gate: derived from the {i['basis']}: {i['value']}")
        else:
            print(f"issue_or_gate: UNVERIFIED (index text; the receipt names no issue or gate): {i['value']}")
        if computed.get("signature"):
            print(f"signature: {computed['signature']}; key from {computed['trust_anchor']['repository']}"
                  f"@{computed['trust_anchor']['commit']}:.aien/verify.pub")
        head = git.head(shelf["repository"])
        if computed["correction"]:
            c = computed["correction"]
            print(f"correction: {c['path']} sha256={c['sha256']} supersedes={c['supersedes_historical_status_for_admission']}"
                  f" claim={c['qualification_claim']}; identical at shelf HEAD {head}")
        else:
            print(f"correction: none at the shelf commit or at shelf HEAD {head}")
        if kind == "omega-qualification-receipt":
            s = computed["source"]
            print(f"source: {s['repository']}@{s['commit']} resolves={s['commit_resolves']} source_check={s['source_check']}"
                  " (repository taken from the index: the receipt does not name it)")
        eff = computed["effective_verdict"]
        print(f"historical: {computed['historical_verdict']}; effective basis: {computed['effective_basis']}")
        rc = exit_for(eff)
        mark = "" if i["verified"] else " issue_or_gate=UNVERIFIED"
        return rc, f"REPLAY {eid}: {eff} rc={rc}{mark}", True
    except Rejected as e:
        return EXIT["REJECTED"], f"REPLAY {eid}: REJECTED {e} rc={EXIT['REJECTED']}", False
    except NotRun as e:
        return EXIT["NOT_RUN"], f"REPLAY {eid}: NOT_RUN {e} rc={EXIT['NOT_RUN']}", False


def load_index(path):
    with open(path, "rb") as f:
        idx = parse_json(f.read(), path)
    if not isinstance(idx, dict) or idx.get("schema") != INDEX_SCHEMA or not isinstance(idx.get("entries"), list):
        raise Rejected("SCHEMA", f"{path} is not an {INDEX_SCHEMA} index")
    unknown = sorted(set(idx) - INDEX_FIELDS)
    if unknown:
        raise Rejected("UNKNOWN_FIELD", f"{path} carries index fields this tool does not know: " + ", ".join(unknown))
    if not isinstance(idx.get("index_version"), int) or not all(isinstance(e, dict) for e in idx["entries"]):
        raise Rejected("SCHEMA", f"{path}: index_version must be an integer and every entry an object")
    ids = [e.get("id") for e in idx["entries"]]
    if len(ids) != len(set(ids)):
        raise Rejected("SCHEMA", f"{path} repeats an entry id")
    return idx


def parse_shelf_arg(s):
    try:
        repo_commit, path = s.split(":", 1)
        repository, commit = repo_commit.split("@", 1)
    except ValueError:
        raise SystemExit("--shelf must be OWNER/REPO@COMMIT:PATH")
    return {"repository": repository, "commit": commit, "path": path}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cache", help="git object cache directory (default: a fresh temporary directory)")
    ap.add_argument("--remote-base", default="https://github.com/", help="prefix for OWNER/REPO fetch URLs")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("replay", help="replay indexed entries")
    r.add_argument("id", nargs="?")
    r.add_argument("--all", action="store_true")
    r.add_argument("--index", default=DEFAULT_INDEX)
    r.add_argument("--bytes", help="replay these local bytes instead of the fetched shelf file (controls)")
    a = sub.add_parser("admit", help="compute a new index entry from pinned commits")
    a.add_argument("--kind", required=True, choices=KINDS)
    a.add_argument("--shelf", required=True, help="OWNER/REPO@COMMIT:PATH")
    a.add_argument("--source-repo", help="implementation repository (omega-qualification-receipt)")
    a.add_argument("--id", required=True, help="entry id (no ':' characters)")
    a.add_argument("--issue-or-gate", help="issue or gate, only for a receipt that names none (recorded UNVERIFIED)")
    args = ap.parse_args(argv)
    if args.cmd == "replay" and bool(args.id) == bool(args.all):
        ap.error("replay needs exactly one of ID or --all")
    if args.cmd == "admit" and args.kind == "omega-qualification-receipt" and not args.source_repo:
        ap.error("--source-repo is required for omega-qualification-receipt")
    with tempfile.TemporaryDirectory() as tmp:
        git = Git(args.cache or tmp, args.remote_base)
        if args.cmd == "admit":
            shelf = parse_shelf_arg(args.shelf)
            try:
                raw = fetch_shelf(git, shelf)
                computed = evaluate(git, args.kind, shelf, args.source_repo, raw, args.issue_or_gate)
            except Rejected as e:
                print(f"ADMIT {args.id}: REJECTED {e} rc=3")
                return EXIT["REJECTED"]
            except NotRun as e:
                print(f"ADMIT {args.id}: NOT_RUN {e} rc=2")
                return EXIT["NOT_RUN"]
            if args.issue_or_gate is not None and computed["issue_or_gate"]["verified"]:
                print(f"ADMIT {args.id}: NOT_RUN --issue-or-gate given, but the receipt names its own "
                      f"({computed['issue_or_gate']['value']}); drop the option rc=2")
                return EXIT["NOT_RUN"]
            if not args.id or ":" in args.id:
                ap.error("--id must be non-empty and contain no ':'")
            entry = {"id": args.id, "issue_or_gate": computed["issue_or_gate"], **computed,
                     "replay": replay_command(args.id)}
            print(json.dumps(entry, indent=1, ensure_ascii=False))
            return 0
        try:
            idx = load_index(args.index)
        except OSError as e:
            print(f"REPLAY: NOT_RUN cannot load index: {e} rc=2")
            return EXIT["NOT_RUN"]
        except Rejected as e:
            print(f"REPLAY: REJECTED index {args.index}: {e} rc=3")
            return EXIT["REJECTED"]
        if args.id:
            entry = next((e for e in idx["entries"] if e.get("id") == args.id), None)
            if entry is None:
                print(f"REPLAY {args.id}: NOT_RUN no such entry in {args.index} rc=2")
                return EXIT["NOT_RUN"]
            rc, last, _ = replay_entry(git, entry, args.bytes)
            print(last)
            return rc
        worst, bad = 0, 0
        for entry in idx["entries"]:
            rc, last, reproduced = replay_entry(git, entry)
            print(last)
            if not reproduced:
                bad += 1
                worst = max(worst, rc)
        n = len(idx["entries"])
        print(f"INDEX {os.path.basename(args.index)} v{idx.get('index_version')}: "
              f"{n - bad}/{n} entries reproduce as indexed rc={worst}")
        return worst


if __name__ == "__main__":
    sys.exit(main())
