"""Tests for the org audit tools. Run: python3 -m unittest discover -s audit/tests -v

Every test builds its own git repository and, where a scanner is involved, a fake
scanner script with a chosen version and exit code, so the tests need no network
and no installed scanners. Each guard has a negative control: the same input with
the guard's condition flipped must change the outcome.
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile, unittest

TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
sys.path.insert(0, TOOLS)
import checks  # noqa: E402
import loc  # noqa: E402
import stamp  # noqa: E402
import status  # noqa: E402
import verify  # noqa: E402

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
           "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}


def sh(*cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, env={**os.environ, **GIT_ENV}).stdout.decode().strip()


def make_repo(root, files):
    os.makedirs(root, exist_ok=True)
    sh("git", "init", "-q", "-b", "main", root)
    return commit(root, files)


def commit(root, files, msg="c"):
    for p, data in files.items():
        full = os.path.join(root, p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
    sh("git", "add", "-A", cwd=root)
    sh("git", "commit", "-q", "-m", msg, cwd=root)
    return sh("git", "rev-parse", "HEAD", cwd=root)


def fake_tool(path, version, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\ncase \"$1\" in --version|-version|version) echo '%s'; exit 0;; esac\n%s\n" % (version, body))
    os.chmod(path, 0o755)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="aien-audit-test-")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tools = os.path.join(self.tmp, "tools")
        os.makedirs(self.tools)
        self.lock = {"schema": "aien-audit-tools-lock/1", "tools": {
            "osv-scanner": {"version": "2.7.0", "version_cmd": ["--version"]},
            "venv/bin/semgrep": {"version": "1.182.1", "version_cmd": ["--version"]}},
            "semgrep_rules": {"config_sha256": ""}}
        self.lock_path = os.path.join(self.tmp, "tools.lock.json")
        self.write_lock()

    def write_lock(self):
        with open(self.lock_path, "w") as fh:
            json.dump(self.lock, fh)

    def run_checks(self, repo, sha, only, name="r"):
        out = os.path.join(self.tmp, "out-" + only.replace(",", "_"))
        doc = checks.run_all(repo, sha, name, out, tools=self.tools, only=only, lock_path=self.lock_path)
        return doc, {c["check"]: c for c in doc["checks"]}, out


class TestCheckerHardening(Base):
    def test_output_hash_covers_written_bytes(self):
        repo = os.path.join(self.tmp, "repo")
        sha = make_repo(repo, {"LICENSE": "MIT License\n", "a.py": "print(1)\n"})
        doc, by, out = self.run_checks(repo, sha, "C2")
        c = by["C2-license"]
        with open(os.path.join(out, "C2-license.json"), "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), c["output_sha256"])

    def test_fork_root_license_outside_diff_is_seen(self):
        repo = os.path.join(self.tmp, "fork")
        base = make_repo(repo, {"License.txt": "Apache License, Version 2.0\n", "up.c": "int x;\n"})
        head = commit(repo, {"ours.c": "int y;\n"})
        doc = checks.run_all(repo, head, "f", os.path.join(self.tmp, "out-fork"), fork_base=base,
                             tools=self.tools, only="C2", lock_path=self.lock_path)
        c2 = {c["check"]: c for c in doc["checks"]}["C2-license"]
        self.assertEqual(c2["summary"]["root"], {"License.txt": "Apache-2.0"})
        self.assertEqual(c2["status"], "PASS")
        # negative control: no licence anywhere in the tree is still flagged
        bare = os.path.join(self.tmp, "bare")
        sha = make_repo(bare, {"a.c": "int z;\n"})
        doc, by, out = self.run_checks(bare, sha, "C2")
        self.assertEqual(by["C2-license"]["status"], "FLAGGED")

    def test_license_signature_survives_reflow(self):
        self.assertEqual(checks.ident("Redistribution and use in source\n   and binary forms"), "BSD")
        self.assertEqual(checks.ident("See docs/license.rst"), "UNRECOGNIZED")  # negative control

    def test_license_ident_takes_spdx_and_earliest_signature(self):
        dual = ("x is dual-licensed\nSPDX-License-Identifier: MIT OR GPL-2.0-only\n\nMIT License\n"
                "Permission is hereby granted, free of charge\nGNU GENERAL PUBLIC LICENSE\n"
                "use the GNU Lesser General Public License instead\n")
        self.assertEqual(checks.ident(dual), "MIT OR GPL-2.0-only")
        gpl = "GNU GENERAL PUBLIC LICENSE\nVersion 2\n... use the GNU Lesser General Public License instead.\n"
        self.assertEqual(checks.ident(gpl), "GPL")  # list order would have said LGPL
        self.assertEqual(checks.ident("Apache License\nVersion 2.0, January 2004\n"), "Apache-2.0")

    def test_spdx_tag_quoted_in_prose_is_not_a_header(self):
        prose = "They carry SPDX-License-Identifier: GPL-2.0-only and remain under\nGPL-2.0-only.\n"
        self.assertEqual(checks.SPDX_RE.findall(prose), [])
        self.assertEqual(checks.SPDX_RE.findall("/* SPDX-License-Identifier: GPL-2.0-only */\n"),
                         ["GPL-2.0-only"])  # negative control: a real header still parses
        self.assertEqual(checks.SPDX_RE.findall("# SPDX-License-Identifier: (MIT OR Apache-2.0) AND BSD-3-Clause\n"),
                         ["(MIT OR Apache-2.0) AND BSD-3-Clause"])
        self.assertEqual(checks.SPDX_RE.findall("// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n"),
                         ["Apache-2.0 WITH LLVM-exception"])

    def test_custom_license_wrapping_apache_text_is_unrecognized(self):
        wrapper = ("Sovereign Resource Commons License 1.0 (SRCL-1.0)\nAll rights reserved.\n"
                   "Licensed under the Apache License, Version 2.0 subject to conditions precedent.\n")
        self.assertEqual(checks.ident(wrapper), "UNRECOGNIZED")
        self.assertEqual(checks.ident("MIT License\nCopyright (c) 2026 X\nPermission is hereby granted, free of charge"),
                         "MIT")  # negative control: an unversioned title before the signature is not a wrapper
        repo = os.path.join(self.tmp, "wrapper")
        sha = make_repo(repo, {"LICENSE": wrapper, "License-History.txt": "old terms\n",
                               "Cargo.toml": '[package]\nlicense = "SRCL-1.0"\n'})
        doc, by, out = self.run_checks(repo, sha, "C2")
        with open(os.path.join(out, "C2-license.json")) as fh:
            kinds = [i["kind"] for i in json.load(fh)["items"]]
        self.assertEqual(kinds, ["unrecognized-root-license", "unrecognized-root-license", "manifest-differs-from-root"])

    def test_nested_license_governs_its_subtree(self):
        agpl = "GNU AFFERO GENERAL PUBLIC LICENSE\n"
        repo = os.path.join(self.tmp, "nested")
        sha = make_repo(repo, {"LICENSE": "Apache License, Version 2.0\n",
                               "adapters/a/LICENSE": agpl,
                               "adapters/a/Cargo.toml": '[package]\nlicense = "AGPL-3.0-or-later"\n',
                               "tools/b/Cargo.toml": '[package]\nlicense = "AGPL-3.0-or-later"\n'})
        doc, by, out = self.run_checks(repo, sha, "C2")
        with open(os.path.join(out, "C2-license.json")) as fh:
            items = json.load(fh)["items"]
        # adapters/a is covered by its own LICENSE; tools/b is the negative control
        self.assertEqual(items, [{"kind": "manifest-differs-from-root", "license": "AGPL-3.0-or-later",
                                  "files": ["tools/b/Cargo.toml"]}])

    def test_fork_link_to_unchanged_upstream_file_resolves(self):
        repo = os.path.join(self.tmp, "fork")
        base = make_repo(repo, {"docs/guide.md": "# g\n"})
        head = commit(repo, {"NOTES.md": "[g](docs/guide.md) [gone](docs/missing.md) `alloc[T](n)`\n"
                                         "See [`docs/also-gone.md`](docs/also-gone.md).\n"})
        doc = checks.run_all(repo, head, "f", os.path.join(self.tmp, "out-fork4"), fork_base=base,
                             tools=self.tools, only="C4", lock_path=self.lock_path)
        c4 = {c["check"]: c for c in doc["checks"]}["C4-internal-links"]
        with open(os.path.join(self.tmp, "out-fork4", "C4-internal-links.json")) as fh:
            targets = [i["target"] for i in json.load(fh)]
        self.assertEqual(targets, ["docs/missing.md", "docs/also-gone.md"])  # missing links are the negative control
        self.assertEqual(c4["count"], 2)

    def test_missing_scanner_is_not_run(self):
        repo = os.path.join(self.tmp, "repo")
        sha = make_repo(repo, {"Cargo.lock": "# lock\n"})
        old = os.environ["PATH"]
        gitbin = os.path.join(self.tmp, "gitonly")
        os.makedirs(gitbin)
        os.symlink(shutil.which("git"), os.path.join(gitbin, "git"))
        os.environ["PATH"] = gitbin  # git, and no osv-scanner anywhere
        try:
            _, by, _ = self.run_checks(repo, sha, "C11")
        finally:
            os.environ["PATH"] = old
        self.assertEqual(by["C11-dep-advisories"]["status"], "NOT_RUN")

    def test_unpinned_version_is_not_run(self):
        repo = os.path.join(self.tmp, "repo")
        sha = make_repo(repo, {"Cargo.lock": "# lock\n"})
        fake_tool(os.path.join(self.tools, "osv-scanner"), "osv-scanner version: 2.7.01", "echo '{\"results\":[]}'")
        _, by, _ = self.run_checks(repo, sha, "C11")
        self.assertEqual(by["C11-dep-advisories"]["status"], "NOT_RUN")
        self.assertIn("pins 2.7.0", by["C11-dep-advisories"]["note"])
        # negative control: the pinned version runs
        fake_tool(os.path.join(self.tools, "osv-scanner"), "osv-scanner version: 2.7.0", "echo '{\"results\":[]}'")
        _, by, _ = self.run_checks(repo, sha, "C11")
        self.assertEqual(by["C11-dep-advisories"]["status"], "PASS")

    def test_osv_exit_codes(self):
        repo = os.path.join(self.tmp, "repo")
        sha = make_repo(repo, {"Cargo.lock": "# lock\n"})
        tool = os.path.join(self.tools, "osv-scanner")
        vuln = ('{"results":[{"source":{"path":"\'"$6"\'/Cargo.lock"},"packages":[{"package":{"name":"bincode",'
                '"version":"1.3.3"},"vulnerabilities":[{"id":"RUSTSEC-2025-0141"}]}]}]}')
        cases = [("echo '{\"results\":[]}'; exit 0", "PASS"),
                 ("echo '%s'; exit 1" % vuln, "FLAGGED"),
                 ("echo '{\"results\":[]}'; exit 1", "NOT_RUN"),  # says vulnerable, lists none
                 ("echo 'no packages' >&2; exit 128", "NOT_RUN"),
                 ("exit 2", "NOT_RUN")]
        for body, want in cases:
            with self.subTest(body=body):
                fake_tool(tool, "osv-scanner version: 2.7.0", body)
                _, by, _ = self.run_checks(repo, sha, "C11")
                self.assertEqual(by["C11-dep-advisories"]["status"], want)

    def test_semgrep_list_error_type_is_incomplete(self):
        self.assertEqual(checks.semgrep_error_type({"type": ["PartialParsing", [{"line": 1}]]}), "PartialParsing")
        self.assertEqual(checks.semgrep_error_type({"type": "Timeout"}), "Timeout")
        repo = os.path.join(self.tmp, "repo")
        sha = make_repo(repo, {"a.py": "print(1)\n"})
        cfg = b"rules: []\n"
        with open(os.path.join(self.tools, "semgrep-config.yaml"), "wb") as fh:
            fh.write(cfg)
        self.lock["semgrep_rules"]["config_sha256"] = hashlib.sha256(cfg).hexdigest()
        self.write_lock()
        sg = os.path.join(self.tools, "venv", "bin", "semgrep")
        write_out = ('while [ "$1" != "--output" ]; do shift; done; out=$2; echo \'%s\' > "$out"; exit 0')
        err = '{"results":[],"errors":[{"type":["PartialParsing",[{"line":1}]]}],"paths":{"skipped":[]}}'
        fake_tool(sg, "1.182.1", write_out % err)
        _, by, _ = self.run_checks(repo, sha, "C5")
        self.assertEqual(by["C5-semgrep"]["status"], "INCOMPLETE")
        # negative control: no errors, no skips -> PASS
        fake_tool(sg, "1.182.1", write_out % '{"results":[],"errors":[],"paths":{"skipped":[]}}')
        _, by, _ = self.run_checks(repo, sha, "C5")
        self.assertEqual(by["C5-semgrep"]["status"], "PASS")
        # a config that is not the pinned one is refused
        with open(os.path.join(self.tools, "semgrep-config.yaml"), "wb") as fh:
            fh.write(b"rules: [] # edited\n")
        _, by, _ = self.run_checks(repo, sha, "C5")
        self.assertEqual(by["C5-semgrep"]["status"], "NOT_RUN")

    def test_crashed_check_is_not_run(self):
        repo = os.path.join(self.tmp, "repo")
        sha = make_repo(repo, {"a.py": "print(1)\n"})
        orig = checks.CHECKS["C2"]
        checks.CHECKS["C2"] = lambda ctx: 1 / 0
        try:
            _, by, _ = self.run_checks(repo, sha, "C2")
        finally:
            checks.CHECKS["C2"] = orig
        self.assertEqual(by["C2-license"]["status"], "NOT_RUN")
        self.assertIn("ZeroDivisionError", by["C2-license"]["note"])


class TestForkLoc(Base):
    def test_modified_upstream_file_counts_added_lines_only(self):
        repo = os.path.join(self.tmp, "fork")
        base = make_repo(repo, {"up.py": "".join("x%d = %d\n" % (i, i) for i in range(100))})
        head = commit(repo, {"up.py": "".join("x%d = %d\n" % (i, i) for i in range(98)) + "y = 1\n\nz = 2\n",
                             "ours.py": "a = 1\nb = 2\n"})
        scc = shutil.which("scc") or os.path.join(os.environ.get("AUDIT_TOOLS", ""), "scc")
        if not os.path.exists(scc):
            self.skipTest("scc not installed (NOT_RUN)")
        doc = loc.count(repo, head, "fork", base, scc, [])
        by = {f["path"]: f for f in doc["files"]}
        self.assertEqual(by["up.py"]["code"], 2)  # y, z; the two deleted lines are not subtracted
        self.assertTrue(by["up.py"]["fork_modified"])
        self.assertEqual(by["ours.py"]["code"], 2)
        self.assertNotIn("fork_modified", by["ours.py"])

    def test_org_totals_dedupe_identical_blobs(self):
        f = {"category": "first_party", "language": "Python", "executable": True, "code": 10, "blob": "b1"}
        docs = [{"repository": "a", "files": [dict(f, path="x.py")]}, {"repository": "b", "files": [dict(f, path="y.py")]}]
        t = loc.org_totals(docs)
        self.assertEqual(t["first_party_executable_code"], 20)
        self.assertEqual(t["distinct_first_party_executable_code"], 10)


def write_stamp(root, ident, st, files):
    d = os.path.join(root, ident, st["subject"]["commit"])
    os.makedirs(d, exist_ok=True)
    for p, data in files.items():
        os.makedirs(os.path.dirname(os.path.join(d, p)), exist_ok=True)
        with open(os.path.join(d, p), "wb") as fh:
            fh.write(data)
    with open(os.path.join(d, "stamp.json"), "w") as fh:
        json.dump(st, fh, indent=1)
    return d


class TestStamp(Base):
    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.tmp, "repo")
        self.sha = make_repo(self.repo, {"LICENSE": "MIT License\n", "a.py": "print(1)\n"})
        self.doc, by, out = self.run_checks(self.repo, self.sha, "C2")
        with open(os.path.join(out, "C2-license.json"), "rb") as fh:
            self.c2 = fh.read()
        self.report = b"# review\nno findings\n"
        self.st = {
            "schema": "aien-audit-stamp/1",
            "subject": {"visibility": "public", "repository": "repo", "kind": "FIRST-PARTY", "commit": self.sha,
                        "tree": sh("git", "rev-parse", self.sha + "^{tree}", cwd=self.repo)},
            "deterministic_checked": {"mode": "full-tree", "fork_base": None, "checker": self.doc["checker"],
                                      "tools_lock_sha256": self.doc["tools_lock_sha256"],
                                      # every FLAGGED item counted as triaged, as a reviewer would record it
                                      "checks": [dict(c, triaged=c["count"] or 0) for c in self.doc["checks"]]},
            "model_reviewed": [{"agent_role": "reviewer", "model": "m", "effort": "high", "files_covered": 2,
                                "files_total": 2, "report": "reviews/r.md",
                                "report_sha256": hashlib.sha256(self.report).hexdigest(), "complete": True}],
            "findings": [], "not_run": [], "verdict": "PASS", "self_reported": False}
        self.stamps = os.path.join(self.tmp, "stamps")

    def put(self, st=None, files=None, ident="repo"):
        return write_stamp(self.stamps, ident, st or self.st,
                           files or {"checks/C2-license.json": self.c2, "reviews/r.md": self.report})

    def test_valid_stamp(self):
        self.assertEqual(stamp.validate(self.put()), [])

    def test_tampered_check_output(self):
        self.assertTrue(any("does not match" in e for e in
                            stamp.validate(self.put(files={"checks/C2-license.json": self.c2 + b" ",
                                                           "reviews/r.md": self.report}))))

    def test_verdict_better_than_contents(self):
        self.st["not_run"] = [{"item": "C1-secrets", "reason": "gitleaks missing"}]
        self.assertTrue(any("better than the contents allow" in e for e in stamp.validate(self.put())))
        self.st["verdict"] = "PASS-WITH-NOTES"  # negative control
        self.assertEqual(stamp.validate(self.put()), [])

    def test_open_high_finding_forces_fail(self):
        self.st["verdict"] = "PASS-WITH-NOTES"
        self.st["findings"] = [{"id": "F1", "source": "MODEL", "severity": "high", "status": "OPEN"}]
        self.assertTrue(any("FAIL" in e for e in stamp.validate(self.put())))

    def test_incomplete_review_cannot_claim_complete(self):
        self.st["model_reviewed"][0]["files_covered"] = 1
        self.assertTrue(any("marked complete" in e for e in stamp.validate(self.put())))

    def test_forbidden_words(self):
        for w in ("pristine", "Approved", "certified"):
            with self.subTest(w=w):
                self.st["note"] = "this repo is %s" % w
                self.assertTrue(any("forbidden word" in e for e in stamp.validate(self.put())))

    def test_fork_requires_fork_diff(self):
        self.st["subject"]["kind"] = "UPSTREAM-FORK"
        self.st["subject"]["upstream"] = {"repository": "up/repo", "base_sha": "a" * 40}
        self.assertTrue(any("fork-diff" in e for e in stamp.validate(self.put())))

    def test_private_stamp_must_not_leak_name(self):
        salts = {"private-01": {"name": "secret-thing", "salt": "ab" * 32}}
        salts["private-01"]["commitment"] = stamp.commitment(salts["private-01"]["salt"], "secret-thing")
        sp = os.path.join(self.tmp, "salts.json")
        with open(sp, "w") as fh:
            json.dump(salts, fh)
        sub = self.st["subject"]
        del sub["repository"]
        sub.update(visibility="private", anonymous_id="private-01", name_commitment=salts["private-01"]["commitment"])
        self.st["self_reported"] = True
        self.assertEqual(stamp.validate(self.put(ident="private-01"), sp), [])
        self.st["note"] = "see secret-thing for context"
        self.assertTrue(any("private repository name" in e for e in stamp.validate(self.put(ident="private-01"), sp)))
        del self.st["note"]
        sub["name_commitment"] = "0" * 64
        self.assertTrue(any("name_commitment" in e for e in stamp.validate(self.put(ident="private-01"), sp)))

    def test_rerun_reproduces_and_detects_substitution(self):
        d = self.put()
        code, msgs = verify.rerun(d, self.repo, "", self.tools, lock_path=self.lock_path)
        self.assertEqual((code, msgs), (0, []))
        # negative control: a stamp whose recorded output was swapped (consistently, so the hash
        # check alone passes) must fail the rerun
        fake = b'{"swapped":true}\n'
        self.st["deterministic_checked"]["checks"][0]["output_sha256"] = hashlib.sha256(fake).hexdigest()
        d = self.put(files={"checks/C2-license.json": fake, "reviews/r.md": self.report})
        self.assertEqual(stamp.validate(d), [])
        code, msgs = verify.rerun(d, self.repo, "", self.tools, lock_path=self.lock_path)
        self.assertEqual(code, 1)


class TestStatus(Base):
    def test_stale_sha_negative_control(self):
        repo = os.path.join(self.tmp, "repo")
        a = make_repo(repo, {"a.py": "1\n"})
        b = commit(repo, {"a.py": "2\n"})
        stamps = os.path.join(self.tmp, "stamps")
        write_stamp(stamps, "repo", {"subject": {"visibility": "public", "repository": "repo", "commit": a},
                                     "verdict": "PASS-WITH-NOTES", "stamped_at": "2026-10-26"}, {})
        self.assertEqual(status.compute(stamps, "org", {"repo": a})["stamps"][0]["state"], "CURRENT")
        self.assertEqual(status.compute(stamps, "org", {"repo": b})["stamps"][0]["state"], "STALE")
        self.assertEqual(status.compute(stamps, "org", {})["stamps"][0]["state"], "UNKNOWN")

    def test_private_is_not_checkable_and_older_superseded(self):
        stamps = os.path.join(self.tmp, "stamps")
        write_stamp(stamps, "private-01", {"subject": {"visibility": "private", "commit": "1" * 40},
                                           "verdict": "PASS-WITH-NOTES", "stamped_at": "2026-10-26"}, {})
        write_stamp(stamps, "repo", {"subject": {"visibility": "public", "commit": "2" * 40}, "stamped_at": "2026-10-01"}, {})
        write_stamp(stamps, "repo", {"subject": {"visibility": "public", "commit": "3" * 40}, "stamped_at": "2026-10-26"}, {})
        rows = status.compute(stamps, "org", {"repo": "3" * 40})["stamps"]
        self.assertEqual([(r["id"], r["state"]) for r in rows],
                         [("private-01", "NOT_CHECKABLE"), ("repo", "CURRENT"), ("repo", "SUPERSEDED")])


if __name__ == "__main__":
    unittest.main()
