#!/usr/bin/env python3
"""Recount the org's lines of code at every public default-branch HEAD.

Usage:
  loc_live.py --config audit/loc/repos.json --tools DIR --latest audit/loc/latest.json
              --history audit/loc/history.jsonl [--date YYYY-MM-DD] [--work DIR] [--no-discover]

repos.json names the public repositories and, for each fork, the upstream repository
and the upstream merge-base we diverged from. Every public repository the GitHub API
lists for the org is counted; one missing from repos.json is counted as first-party
full-tree if it is not a fork, and is NOT_COUNTED (with the reason) if it is a fork
without a pinned base, so new repositories never vanish from the total silently.

Each repository is fetched at its HEAD and counted with loc.py (forks in fork-diff
mode against the pinned base, which must still be an ancestor of HEAD; otherwise
the fork is NOT_COUNTED until the base is re-pinned). Totals come from
loc.org_totals: `distinct_*` counts each identical blob once across repositories.

latest.json carries no clock time, so an unchanged org rewrites identical bytes.
history.jsonl gains one line, stamped with --date, only when a HEAD or a total moved.
Private repositories are not counted here; nobody outside can re-run them.
Exit 0 when every listed repository was counted, 3 when any is NOT_COUNTED.
"""
import argparse, datetime, hashlib, json, os, subprocess, sys, tempfile, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import loc  # noqa: E402


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True,
                          env=dict(os.environ, GIT_TERMINAL_PROMPT="0")).stdout


def org_public_repos(org):
    """[(name, fork, archived)] for every public repository, from the REST API."""
    out, page = [], 1
    tok = os.environ.get("GITHUB_TOKEN", "")
    while True:
        req = urllib.request.Request("https://api.github.com/orgs/%s/repos?type=public&per_page=100&page=%d" % (org, page),
                                     headers={"Accept": "application/vnd.github+json",
                                              **({"Authorization": "Bearer " + tok} if tok else {})})
        with urllib.request.urlopen(req, timeout=60) as r:
            batch = json.load(r)
        out += [(b["name"], b["fork"], b["archived"]) for b in batch if not b["private"]]
        if len(batch) < 100:
            return out
        page += 1


def fetch(org, name, work, fork_base):
    gd = os.path.join(work, name + ".git")
    if not os.path.isdir(gd):
        git("init", "-q", "--bare", gd)
    url = "https://github.com/%s/%s" % (org, name)
    head = git("ls-remote", url, "HEAD").decode().split("\t", 1)[0].strip()
    if fork_base:
        # blobless: the fork diff reads only the blobs our commits touched; the rest are never fetched.
        # The pinned upstream base arrives with HEAD's history when it is still an ancestor.
        if not _has_remote(gd):
            git("-C", gd, "remote", "add", "origin", url)
            git("-C", gd, "config", "remote.origin.promisor", "true")
            git("-C", gd, "config", "remote.origin.partialclonefilter", "blob:none")
            git("-C", gd, "config", "extensions.partialClone", "origin")
        git("-C", gd, "fetch", "-q", "--filter=blob:none", "origin", head)
    else:
        git("-C", gd, "fetch", "-q", "--depth", "1", url, head)
    return gd, head


def _has_remote(gd):
    return subprocess.run(["git", "-C", gd, "remote", "get-url", "origin"], capture_output=True).returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--tools", required=True)
    ap.add_argument("--latest", required=True)
    ap.add_argument("--history", required=True)
    ap.add_argument("--date", default=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"))
    ap.add_argument("--work", default="")
    ap.add_argument("--no-discover", action="store_true", help="count only repos.json (tests)")
    a = ap.parse_args()
    with open(a.config) as fh:
        cfg = json.load(fh)
    org = cfg["org"]
    listed = {r["name"]: r for r in cfg["repositories"]}
    if not a.no_discover:
        for name, fork, archived in org_public_repos(org):
            if name not in listed:
                listed[name] = {"name": name, "kind": "UPSTREAM-FORK" if fork else ("ARCHIVED" if archived else "FIRST-PARTY"),
                                "unlisted": True}
    scc = os.path.join(a.tools, "scc")
    classify = os.path.join(HERE, "classify.json")
    extra_all = json.load(open(classify)) if os.path.exists(classify) else {}
    docs, rows = [], []
    with tempfile.TemporaryDirectory(prefix="aien-loc-live-") as tmp:
        work = a.work or tmp
        for name in sorted(listed):
            r = listed[name]
            row = {"repository": name, "kind": r["kind"]}
            base = (r.get("upstream") or {}).get("base_sha", "")
            if r["kind"] == "UPSTREAM-FORK" and not base:
                rows.append(dict(row, state="NOT_COUNTED", reason="fork without a pinned upstream base in repos.json"))
                continue
            try:
                gd, head = fetch(org, name, work, base)
                if base and subprocess.run(["git", "-C", gd, "merge-base", "--is-ancestor", base, head],
                                           capture_output=True).returncode != 0:
                    rows.append(dict(row, state="NOT_COUNTED", commit=head,
                                     reason="pinned upstream base is not an ancestor of HEAD; re-pin it"))
                    continue
                doc = loc.count(gd, head, name, base, scc, extra_all.get(name, []))
            except (subprocess.CalledProcessError, OSError, ValueError) as e:
                rows.append(dict(row, state="NOT_COUNTED", reason="%s: %s" % (type(e).__name__, str(e)[:200])))
                continue
            docs.append(doc)
            rows.append(dict(row, state="COUNTED", commit=doc["commit"], mode=doc["mode"],
                             fork_base=doc.get("fork_base"), unlisted=bool(r.get("unlisted")),
                             first_party_executable_code=doc["first_party_executable_code"],
                             sha256=hashlib.sha256(loc.canonical(doc)).hexdigest()))
    latest = {"schema": "aien-audit-loc-live/1", "org": org, "loc_tool": loc.TOOL_VERSION,
              "scc_version": cfg.get("scc_version"), "repositories": rows, "totals": loc.org_totals(docs),
              "not_counted": sum(r["state"] == "NOT_COUNTED" for r in rows),
              "scope": "public repositories only; private repositories are not counted here"}
    old = None
    if os.path.exists(a.latest):
        with open(a.latest) as fh:
            old = json.load(fh)
    with open(a.latest, "w") as fh:
        fh.write(json.dumps(latest, indent=1, sort_keys=True) + "\n")
    if old != latest:
        line = {"date": a.date, "totals": latest["totals"], "not_counted": latest["not_counted"],
                "heads": {r["repository"]: r.get("commit") for r in rows}}
        with open(a.history, "a") as fh:
            fh.write(json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n")
    t = latest["totals"]
    print("repos=%d counted=%d not_counted=%d first_party_executable=%d distinct=%d" % (
        len(rows), len(docs), latest["not_counted"], t["first_party_executable_code"], t["distinct_first_party_executable_code"]))
    sys.exit(3 if latest["not_counted"] else 0)


if __name__ == "__main__":
    main()
