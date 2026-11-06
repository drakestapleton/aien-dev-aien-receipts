"""Offline tests for tools/replay_receipt.py (DRA-167).

Every test builds disposable Git repositories under a temporary directory and
serves them through file:// URLs, so the suite needs no network and never
touches the shelf in this checkout. Run from the repository root:

    python3 -m unittest discover -s tests -v
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join(ROOT, "tools", "replay_receipt.py")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import replay_receipt as rr  # noqa: E402

GIT_ID = ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false"]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def sh(*args, cwd=None, data=None):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, input=data).stdout


class Key:
    def __init__(self, d, name):
        self.pem = os.path.join(d, name + ".pem")
        sh("openssl", "genpkey", "-algorithm", "ed25519", "-out", self.pem)
        der = sh("openssl", "pkey", "-in", self.pem, "-pubout", "-outform", "DER")
        self.pub = der[-32:].hex()
        self.dir = d

    def sign(self, msg):
        m, s = os.path.join(self.dir, "m.bin"), os.path.join(self.dir, "s.bin")
        with open(m, "wb") as f:
            f.write(msg)
        sh("openssl", "pkeyutl", "-sign", "-inkey", self.pem, "-rawin", "-in", m, "-out", s)
        with open(s, "rb") as f:
            return f.read().hex()


class Remotes:
    def __init__(self, root):
        self.root = root

    def commit(self, name, files, msg="fixture"):
        d = os.path.join(self.root, name)
        if not os.path.isdir(d):
            os.makedirs(d)
            sh("git", "init", "-q", "-b", "main", cwd=d)
            sh("git", "config", "uploadpack.allowFilter", "true", cwd=d)
            sh("git", "config", "uploadpack.allowAnySHA1InWant", "true", cwd=d)
        for path, data in files.items():
            p = os.path.join(d, path)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
        sh("git", "add", "-A", cwd=d)
        sh("git", *GIT_ID, "commit", "-q", "--allow-empty", "-m", msg, cwd=d)
        return sh("git", "rev-parse", "HEAD", cwd=d).decode().strip()


def bundle(key, repo, commit, checks, verdict, signer=None):
    b = {
        "schema": rr.BUNDLE_SCHEMA, "repository": "github.com/" + repo, "commit": commit,
        "executor": {"class": "spark", "id": sha(bytes.fromhex(key.pub)), "machine_digest": "a" * 64},
        "tree_digest": "b" * 64, "graph_digest": "c" * 64, "receipt_id_scheme": "sha256-canonical-json",
        "started_utc": "2026-11-06T00:00:00Z", "finished_utc": "2026-11-06T00:01:00Z",
        "checks": [{"backend": "host", "check_id": "d" * 64, "exactness": "EXACT", "gate": g, "receipt": "e" * 64,
                    "required": True, "status": "run", "verdict": v} for g, v in checks],
        "verdict": verdict,
    }
    signer = signer or key
    b["signature"] = {"alg": "ed25519", "pubkey": signer.pub, "sig": signer.sign(rr.canonical(b))}
    return b


def receipt(commit, **fields):
    d = {"status": "QUALIFIED / PASS", "milestone": "MILESTONE T", "contract_id": "CONTRACT-T", "git_commit": commit,
         "artifacts": {"build/omegatool": {"sha256": "0" * 64}, "src/a.c": {"sha256": sha(b"int a;\n")}}}
    d.update(fields)
    return json.dumps({k: v for k, v in d.items() if v is not None}, indent=2).encode()


def correction(path, digest, cid="T-1"):
    return json.dumps({"schema": rr.CORRECTION_SCHEMA, "correction_id": cid, "recorded_on": "2026-11-06",
                       "corrects": {"repository": "aien-dev/omega-evidence", "path": path, "sha256": digest},
                       "disposition": {"supersedes_historical_status_for_admission": True,
                                       "qualification_claim": "REFUSED_UNSUPPORTED_PROVENANCE"}}).encode()


OMEGA_ISSUE = {"value": "Omega MILESTONE T qualification (CONTRACT-T)",
               "basis": "receipt fields milestone and contract_id", "verified": True}


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tmp.name
        cls.base = "file://" + os.path.join(t, "remotes") + "/"
        cls.cache = os.path.join(t, "cache")
        r = Remotes(os.path.join(t, "remotes"))
        trusted, other = Key(t, "trusted"), Key(t, "other")
        # Source repository: the base commit carries the trust anchor.
        r.commit("aien-dev/demo", {".aien/verify.pub": (trusted.pub + "\n").encode(),
                                   ".aien/always": b"# required\nG-ONE\n"}, "base")
        c = [r.commit("aien-dev/demo", {"f": str(i).encode()}, f"c{i}") for i in range(6)]
        good = bundle(trusted, "aien-dev/demo", c[0], [("G-ONE", "PASS"), ("G-TWO", "PASS")], "PASS")
        fail = bundle(trusted, "aien-dev/demo", c[1], [("G-ONE", "FAIL")], "FAIL")
        tampered = bundle(trusted, "aien-dev/demo", c[2], [("G-ONE", "FAIL")], "FAIL")
        tampered["checks"][0]["verdict"], tampered["verdict"] = "PASS", "PASS"
        alien = bundle(trusted, "aien-dev/demo", c[3], [("G-ONE", "PASS")], "PASS", signer=other)
        missing = bundle(trusted, "aien-dev/demo", c[4], [("G-TWO", "PASS")], "PASS")
        corrected = bundle(trusted, "aien-dev/demo", c[5], [("G-ONE", "PASS")], "PASS")
        cls.good_bytes = rr.canonical(good)
        cls.bundles = {}
        files = {}
        for name, b in (("good", good), ("fail", fail), ("tampered", tampered), ("alien", alien),
                        ("missing", missing), ("corrected", corrected)):
            path = f"demo/{b['commit']}/bundle.json"
            files[path] = rr.canonical(b)
            cls.bundles[name] = path
        files[f"demo/{c[5]}/bundle.correction.json"] = b"{}\n"
        cls.shelf = r.commit("aien-dev/aien-receipts", files, "shelf")
        # Omega receipts: source commits, then a shelf without and with corrections.
        o1 = r.commit("aien-dev/omega-mv", {"src/a.c": b"int a;\n"}, "o1")
        o2 = r.commit("aien-dev/omega-mv", {"src/a.c": b"int a2;\n"}, "o2")
        cls.receipts = {"ok.json": receipt(o1), "mismatch.json": receipt(o2), "unresolved.json": receipt("f" * 40),
                        "unbound.json": receipt(o1), "nameless.json": receipt(o1, milestone=None, contract_id=None)}
        cls.e1 = r.commit("aien-dev/omega-evidence", dict(cls.receipts), "receipts")
        cls.e2 = r.commit("aien-dev/omega-evidence", {
            "ok.correction.json": correction("ok.json", sha(cls.receipts["ok.json"])),
            "unbound.correction.json": correction("unbound.json", "1" * 64)}, "corrections")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def tool(self, *args, base=None, cache=None):
        p = subprocess.run([sys.executable, TOOL, "--remote-base", base or self.base, "--cache", cache or self.cache,
                            *args], capture_output=True, text=True)
        lines = p.stdout.strip().splitlines()
        return p.returncode, (lines[-1] if lines else p.stderr.strip()), p.stdout

    def admit(self, eid, kind, repo, commit, path, source=None, issue=None, **where):
        args = ["admit", "--kind", kind, "--shelf", f"{repo}@{commit}:{path}", "--id", eid]
        if source:
            args += ["--source-repo", source]
        if issue is not None:
            args += ["--issue-or-gate", issue]
        rc, last, out = self.tool(*args, **where)
        return rc, (json.loads(out) if rc == 0 else last)

    def index(self, *entries, **extra):
        path = os.path.join(self.tmp.name, f"index-{len(os.listdir(self.tmp.name))}.json")
        with open(path, "w") as f:
            json.dump({"schema": rr.INDEX_SCHEMA, "index_version": 2, "entries": list(entries), **extra}, f)
        return path

    def bundle_entry(self, name):
        return self.admit(f"demo-{name}", "signed-bundle", "aien-dev/aien-receipts", self.shelf, self.bundles[name])

    def omega_entry(self, path, shelf_commit, issue=None, **where):
        return self.admit(f"omega-{path}", "omega-qualification-receipt", "aien-dev/omega-evidence",
                          shelf_commit, path, "aien-dev/omega-mv", issue, **where)

    # -- canonical encoder: golden cases from evidence.rs (aien-sovereign-core@c26f4d7a)
    def test_canonical_sorts_keys_and_is_compact(self):
        v = {"b": [1, True, None], "a": {"z": "x", "y": -3}}
        self.assertEqual(rr.canonical(v), b'{"a":{"y":-3,"z":"x"},"b":[1,true,null]}')

    def test_canonical_escapes(self):
        v = "a\"b\\c\nd\r\te\x1ff\x7f\xe9"
        self.assertEqual(rr.canonical(v), '"a\\"b\\\\c\\nd\\r\\te\\u001ff\x7f\xe9"'.encode("utf-8"))

    def test_canonical_rejects_floats(self):
        for v in ({"x": 1.5}, [0.0]):
            with self.assertRaises(ValueError):
                rr.canonical(v)

    def test_verdict_algebra(self):
        self.assertEqual(rr.compute_verdict([("A", True, "run", "PASS"), ("B", False, "run", "FAIL")]), "PASS")
        self.assertEqual(rr.compute_verdict([("A", True, "run", "PASS"), ("B", True, "run", "FAIL")]), "FAIL")
        self.assertEqual(rr.compute_verdict([("A", True, "not_run", "NOT_RUN")]), "NOT_RUN")

    # -- signed bundles
    def test_signed_pass_bundle_replays_pass(self):
        rc, entry = self.bundle_entry("good")
        self.assertEqual(rc, 0, entry)
        self.assertEqual(set(entry), rr.ENTRY_FIELDS["signed-bundle"])
        self.assertEqual(entry["shelf"]["sha256"], sha(self.good_bytes))
        self.assertEqual(entry["issue_or_gate"], {"value": "aien-dev/demo required gates: G-ONE, G-TWO",
                                                  "basis": "bundle repository and the gate of every required check",
                                                  "verified": True})
        rc, last, out = self.tool("replay", "--index", self.index(entry), entry["id"])
        self.assertEqual((rc, last), (0, "REPLAY demo-good: PASS rc=0"))
        self.assertIn("correction: none at the shelf commit or at shelf HEAD", out)

    def test_corrupted_copy_is_rejected(self):
        rc, entry = self.bundle_entry("good")
        corrupt = bytearray(self.good_bytes)
        corrupt[corrupt.index(b'"verdict":"PASS"') + 11] ^= 0x01
        p = os.path.join(self.tmp.name, "corrupt.json")
        with open(p, "wb") as f:
            f.write(corrupt)
        rc, last, _ = self.tool("replay", "--index", self.index(entry), entry["id"], "--bytes", p)
        self.assertEqual(rc, 3)
        self.assertIn("REJECTED DIGEST_MISMATCH", last)

    def test_authenticated_fail_bundle_replays_fail(self):
        rc, entry = self.bundle_entry("fail")
        self.assertEqual(rc, 0, entry)
        rc, last, _ = self.tool("replay", "--index", self.index(entry), entry["id"])
        self.assertEqual((rc, last), (1, "REPLAY demo-fail: FAIL rc=1"))

    def test_tampered_bundle_bad_signature(self):
        rc, last = self.bundle_entry("tampered")
        self.assertEqual(rc, 3)
        self.assertIn("BAD_SIGNATURE", last)

    def test_key_not_on_base_branch(self):
        rc, last = self.bundle_entry("alien")
        self.assertEqual(rc, 3)
        self.assertIn("UNKNOWN_KEY", last)

    def test_missing_required_gate(self):
        rc, last = self.bundle_entry("missing")
        self.assertEqual(rc, 3)
        self.assertIn("MISSING_REQUIRED_CHECK: G-ONE", last)

    def test_bundle_with_a_correction_file_is_rejected(self):
        rc, last = self.bundle_entry("corrected")
        self.assertEqual(rc, 3)
        self.assertIn("CORRECTION_UNSUPPORTED", last)

    def test_kind_on_the_wrong_shelf_is_rejected(self):
        rc, last = self.admit("x", "signed-bundle", "aien-dev/omega-evidence", self.e2, "ok.json")
        self.assertEqual(rc, 3)
        self.assertIn("SHELF_REPOSITORY", last)

    # -- omega receipts and correction precedence
    def test_correction_supersedes_historical_pass(self):
        self.assertEqual(sh("git", "-C", os.path.join(self.tmp.name, "remotes/aien-dev/omega-evidence"),
                            "show", f"{self.e2}:ok.json"), self.receipts["ok.json"])
        rc, entry = self.omega_entry("ok.json", self.e2)
        self.assertEqual(rc, 0, entry)
        self.assertEqual(set(entry), rr.ENTRY_FIELDS["omega-qualification-receipt"])
        self.assertEqual(entry["historical_verdict"], "QUALIFIED / PASS")
        rc, last, _ = self.tool("replay", "--index", self.index(entry), entry["id"])
        self.assertEqual((rc, last), (4, "REPLAY omega-ok.json: REFUSED_UNSUPPORTED_PROVENANCE rc=4"))
        # The commit before the correction is not admissible while the HEAD carries one.
        rc, last = self.omega_entry("ok.json", self.e1)
        self.assertEqual(rc, 3)
        self.assertIn(f"REJECTED STALE_CORRECTION: ok.correction.json at aien-dev/omega-evidence HEAD {self.e2}", last)

    def test_index_that_misses_a_correction_drifts(self):
        rc, entry = self.omega_entry("ok.json", self.e2)
        stale = json.loads(json.dumps(entry))
        stale["correction"] = None
        stale["effective_verdict"] = "PASS"
        rc, last, _ = self.tool("replay", "--index", self.index(stale), stale["id"])
        self.assertEqual(rc, 3)
        self.assertIn("INDEX_DRIFT", last)
        self.assertIn("correction", last)

    def test_correction_landing_after_the_indexed_commit_fails(self):
        # The index stays on the old commit while a correction lands one commit later.
        root = os.path.join(self.tmp.name, "late")
        where = {"base": "file://" + root + "/", "cache": os.path.join(self.tmp.name, "late-cache")}
        r = Remotes(root)
        o1 = r.commit("aien-dev/omega-mv", {"src/a.c": b"int a;\n"}, "o1")
        data = receipt(o1)
        s1 = r.commit("aien-dev/omega-evidence", {"late.json": data}, "receipt")
        rc, entry = self.omega_entry("late.json", s1, **where)
        self.assertEqual(rc, 0, entry)
        index = self.index(entry)
        rc, last, out = self.tool("replay", "--index", index, entry["id"], **where)
        self.assertEqual((rc, last), (0, "REPLAY omega-late.json: PASS rc=0"), out)  # positive control
        s2 = r.commit("aien-dev/omega-evidence", {"late.correction.json": correction("late.json", sha(data))}, "corr")
        rc, last, _ = self.tool("replay", "--index", index, entry["id"], **where)
        self.assertEqual(rc, 3, last)
        self.assertIn(f"REJECTED STALE_CORRECTION: late.correction.json at aien-dev/omega-evidence HEAD {s2} "
                      f"has sha256", last)
        rc, last, _ = self.tool("replay", "--all", "--index", index, **where)
        self.assertEqual(rc, 3, last)
        self.assertTrue(last.endswith("0/1 entries reproduce as indexed rc=3"), last)
        # Re-admitted at the HEAD, the correction decides.
        rc, fresh = self.omega_entry("late.json", s2, **where)
        self.assertEqual(rc, 0, fresh)
        self.assertEqual(fresh["effective_verdict"], "REFUSED_UNSUPPORTED_PROVENANCE")
        # A correction rewritten after the pinned commit fails the same way.
        r.commit("aien-dev/omega-evidence", {"late.correction.json": correction("late.json", sha(data), "T-2")}, "c2")
        rc, last, _ = self.tool("replay", "--index", self.index(fresh), fresh["id"], **where)
        self.assertEqual(rc, 3, last)
        self.assertIn("STALE_CORRECTION", last)

    def test_unbound_correction_is_rejected(self):
        rc, last = self.omega_entry("unbound.json", self.e2)
        self.assertEqual(rc, 3)
        self.assertIn("CORRECTION_UNBOUND", last)

    def test_source_mismatch_is_refused(self):
        rc, entry = self.omega_entry("mismatch.json", self.e1)
        self.assertEqual(rc, 0, entry)
        self.assertEqual(entry["source"]["artifacts"][1]["at_source_commit"], "mismatch")
        rc, last, _ = self.tool("replay", "--index", self.index(entry), entry["id"])
        self.assertEqual((rc, last), (4, "REPLAY omega-mismatch.json: REFUSED_SOURCE_PROVENANCE rc=4"))

    def test_unresolved_source_commit_is_refused(self):
        rc, entry = self.omega_entry("unresolved.json", self.e1)
        self.assertEqual(rc, 0, entry)
        self.assertFalse(entry["source"]["commit_resolves"])
        self.assertEqual(entry["effective_verdict"], "REFUSED_SOURCE_PROVENANCE")

    # -- issue_or_gate and unknown fields
    def test_edited_issue_or_gate_fails(self):
        rc, entry = self.omega_entry("mismatch.json", self.e1)
        self.assertEqual(entry["issue_or_gate"], OMEGA_ISSUE)
        for edit in ({"value": "hardware qualified on GB10"},
                     {"basis": rr.UNVERIFIED_ISSUE_BASIS, "verified": False}):
            edited = json.loads(json.dumps(entry))
            edited["issue_or_gate"].update(edit)
            rc, last, _ = self.tool("replay", "--index", self.index(edited), edited["id"])
            self.assertEqual(rc, 3, last)
            self.assertTrue(last.endswith("INDEX_DRIFT: recomputed fields differ from the index: issue_or_gate rc=3"),
                            last)

    def test_unknown_entry_field_fails(self):
        rc, entry = self.bundle_entry("good")
        entry["qualification"] = "hardware qualified on GB10"
        rc, last, _ = self.tool("replay", "--index", self.index(entry), entry["id"])
        self.assertEqual(rc, 3, last)
        self.assertIn("REJECTED UNKNOWN_FIELD", last)
        self.assertIn("qualification", last)

    def test_unknown_index_field_fails(self):
        rc, entry = self.bundle_entry("good")
        rc, last, _ = self.tool("replay", "--all", "--index", self.index(entry, hardware="qualified on GB10"))
        self.assertEqual(rc, 3, last)
        self.assertIn("REJECTED", last)
        self.assertIn("UNKNOWN_FIELD", last)

    def test_edited_replay_command_fails(self):
        rc, entry = self.bundle_entry("good")
        entry["replay"] = "true"
        rc, last, _ = self.tool("replay", "--index", self.index(entry), entry["id"])
        self.assertEqual(rc, 3, last)
        self.assertIn("INDEX_DRIFT", last)

    def test_issue_not_in_receipt_is_marked_unverified(self):
        rc, last = self.omega_entry("nameless.json", self.e2)
        self.assertEqual(rc, 3)
        self.assertIn("names no issue or gate", last)
        rc, entry = self.omega_entry("nameless.json", self.e2, issue="DRA-0 test gate")
        self.assertEqual(rc, 0, entry)
        self.assertEqual(entry["issue_or_gate"], {"value": "DRA-0 test gate", "basis": rr.UNVERIFIED_ISSUE_BASIS,
                                                  "verified": False})
        rc, last, out = self.tool("replay", "--index", self.index(entry), entry["id"])
        self.assertEqual((rc, last), (0, "REPLAY omega-nameless.json: PASS rc=0 issue_or_gate=UNVERIFIED"))
        self.assertIn("issue_or_gate: UNVERIFIED", out)
        # A receipt that names its own issue does not take operator text.
        rc, last = self.omega_entry("ok.json", self.e2, issue="DRA-0 test gate")
        self.assertEqual(rc, 2)
        self.assertIn("drop the option", last)

    # -- whole index and unreachable inputs
    def test_replay_all(self):
        entries = [self.bundle_entry("good")[1], self.bundle_entry("fail")[1], self.omega_entry("ok.json", self.e2)[1]]
        rc, last, _ = self.tool("replay", "--all", "--index", self.index(*entries))
        self.assertEqual(rc, 0, last)
        self.assertTrue(last.endswith("3/3 entries reproduce as indexed rc=0"), last)

    def test_unreachable_remote_is_not_run(self):
        rc, entry = self.bundle_entry("good")
        rc, last, _ = self.tool("replay", "--index", self.index(entry), entry["id"],
                                base="file://" + os.path.join(self.tmp.name, "nowhere") + "/")
        self.assertEqual(rc, 2)
        self.assertIn("NOT_RUN cannot reach", last)


class ShippedIndexTests(unittest.TestCase):
    """Structure of index/receipt_index.json; replaying it needs the network (docs/receipt-index.md)."""

    def test_shipped_index_shape(self):
        idx = rr.load_index(rr.DEFAULT_INDEX)
        self.assertEqual(idx["index_version"], 2)
        for e in idx["entries"]:
            self.assertEqual(set(e), rr.ENTRY_FIELDS[e["kind"]])
            self.assertNotIn(":", e["id"])
            self.assertEqual(e["shelf"]["repository"], rr.SHELF_REPOS[e["kind"]])
            self.assertEqual(e["replay"], rr.replay_command(e["id"]))
            self.assertTrue(rr.is_hex(e["shelf"]["sha256"], 64) and rr.is_hex(e["shelf"]["commit"], 40))
            self.assertTrue(e["issue_or_gate"]["verified"], e["id"])
            self.assertIn(rr.exit_for(e["effective_verdict"]), (0, 1, 4))
            c = e["correction"]
            if c and c["supersedes_historical_status_for_admission"]:
                self.assertEqual(e["effective_verdict"], c["qualification_claim"])

    def test_shipped_index_refuses_m8_and_m9(self):
        idx = rr.load_index(rr.DEFAULT_INDEX)
        by_id = {e["id"]: e for e in idx["entries"]}
        for m in ("omega-evidence/M8", "omega-evidence/M9"):
            self.assertEqual(by_id[m]["historical_verdict"], "QUALIFIED / PASS")
            self.assertEqual(by_id[m]["effective_verdict"], "REFUSED_UNSUPPORTED_PROVENANCE")

    def test_shipped_m4_issue_comes_from_the_receipt(self):
        by_id = {e["id"]: e for e in rr.load_index(rr.DEFAULT_INDEX)["entries"]}
        self.assertEqual(by_id["omega-evidence/M4"]["issue_or_gate"]["value"],
                         "Omega MILESTONE 4 — OMEGA_SEMANTICS qualification (CONTRACT-OMEGA-SEMANTICS-M4)")


if __name__ == "__main__":
    unittest.main()
