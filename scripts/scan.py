#!/usr/bin/env python3

import os
import sys
import time
import yaml
import json
import subprocess
import requests
from datetime import datetime, timezone

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

TOKEN            = os.environ.get("GH_TOKEN", "")
ORG_FILTER       = os.environ.get("ORG_FILTER", "").strip()
REPO_FILTER      = os.environ.get("REPO_FILTER", "").strip()
GOVERNANCE_REPO  = os.environ.get("GOVERNANCE_REPO", "qualcomm-governance/org-governance")

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28"
}

SEARCH_DELAY     = 2.5    # seconds between Search API calls (30 req/min limit)
CHUNK_SIZE       = 30     # repos per chunk before pausing
CHUNK_PAUSE      = 60     # seconds to pause between chunks
REPO_PAGE_SIZE   = 100    # max repos per page (GitHub API max)
MAX_REPOS_PER_ORG = 5000  # safety cap per org


# ══════════════════════════════════════════════════════════════════════════════
# GITHUB API HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def gh_get(url, params=None, retries=3):
    """
    GET request with retry logic and rate limit handling.
    Returns parsed JSON or None on failure.
    """
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=HEADERS, params=params, timeout=30)

            # Rate limited — wait until reset
            if resp.status_code == 403:
                reset_ts  = int(resp.headers.get("X-RateLimit-Reset", time.time() + 60))
                wait_secs = max(reset_ts - int(time.time()), 10)
                print(f"  ⏳ Rate limited (attempt {attempt}/{retries}). Waiting {wait_secs}s ...")
                time.sleep(wait_secs)
                continue

            # Search index unavailable for this repo — skip silently
            if resp.status_code == 422:
                return None

            # Not found
            if resp.status_code == 404:
                print(f"  ⚠️  404 Not Found: {url}")
                return None

            resp.raise_for_status()
            return resp.json()

        except requests.exceptions.Timeout:
            print(f"  ⚠️  Timeout on attempt {attempt}/{retries}: {url}")
            time.sleep(5 * attempt)

        except requests.exceptions.RequestException as e:
            print(f"  ⚠️  Request error on attempt {attempt}/{retries}: {e}")
            time.sleep(5 * attempt)

    print(f"  ❌ All {retries} attempts failed for: {url}")
    return None


def list_repos(org, visibility="public"):
    """
    Paginate through all repos in a GitHub org.
    visibility: 'public' | 'private' | 'all'
    Returns list of full repo names e.g. ['qualcomm-ai/my-repo']
    """
    repos = []
    page  = 1

    while True:
        data = gh_get(
            f"https://api.github.com/orgs/{org}/repos",
            params={
                "type": visibility,
                "per_page": REPO_PAGE_SIZE,
                "page": page
            }
        )

        if not data:
            break

        repos.extend([r["full_name"] for r in data])
        print(f"    Page {page}: fetched {len(data)} repos (total so far: {len(repos)})")

        # Last page reached
        if len(data) < REPO_PAGE_SIZE:
            break

        page     += 1
        time.sleep(0.5)   # gentle on REST API

        if len(repos) >= MAX_REPOS_PER_ORG:
            print(f"  ⚠️  Safety cap reached ({MAX_REPOS_PER_ORG} repos) for org: {org}")
            break

    return repos


def search_prt_in_repo(repo_full_name):
    """
    Search for pull_request_target usage in .github/workflows/ of a repo.
    Returns list of matching file paths, empty list if none found.
    """
    time.sleep(SEARCH_DELAY)   # respect search rate limit

    data = gh_get(
        "https://api.github.com/search/code",
        params={
            "q": f"pull_request_target repo:{repo_full_name} path:.github/workflows",
            "per_page": 10
        }
    )

    if not data:
        return []

    return [item["path"] for item in data.get("items", [])]


# ══════════════════════════════════════════════════════════════════════════════
# GITHUB CLI HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def run_gh(args, check=True):
    """Run a gh CLI command and return stdout string."""
    result = subprocess.run(
        ["gh"] + args,
        capture_output=True,
        text=True,
        check=False
    )
    if check and result.returncode != 0:
        print(f"  ⚠️  gh CLI error: {result.stderr.strip()}")
    return result.stdout.strip()


def issue_exists(repo, label):
    """
    Returns the issue number (str) if an open issue with the given label
    exists in the repo, otherwise returns empty string.
    """
    return run_gh([
        "issue", "list",
        "--repo", repo,
        "--label", label,
        "--state", "open",
        "--json", "number",
        "-q", ".[0].number"
    ], check=False)


# ══════════════════════════════════════════════════════════════════════════════
# ISSUE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def create_repo_issue(repo, files_str, security_team):
    """
    File a security issue directly on the violating repo.
    Skips if an open prt-violation issue already exists.
    """
    existing = issue_exists(repo, "prt-violation")
    if existing:
        print(f"    ⏭️  Open issue #{existing} already exists in {repo} — skipping")
        return

    body = f"""## 🔐 Action Required: Remove `pull_request_target`

**Detected in:** `{files_str}`
**Policy:** Banned in public repos per Qualcomm Technologies Inc. org security policy

---

### Why This Is Dangerous

`pull_request_target` runs workflows with **write permissions and full secrets access**
even when triggered by a pull request from a **fork**.

This means an external contributor can submit a malicious PR that:
- Exfiltrates all repository secrets
- Pushes commits with write access
- Modifies release artifacts

See: [Keeping your GitHub Actions and workflows secure](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)

---

### Fix

**Replace:**
```yaml
on:
  pull_request_target:
```

**With:**
```yaml
on:
  pull_request:
```

> If you have a genuine use case that requires `pull_request_target`, contact
> @{security_team} for a security review before proceeding.

---

### Resources
- [Internal Fix Guide](https://github.com/{GOVERNANCE_REPO}/wiki/safe-workflow-triggers)
- [GitHub Security Hardening Docs](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

---
*Raised by: Qualcomm Org Security Automation*
*Security contact: @{security_team}*"""

    run_gh([
        "issue", "create",
        "--repo", repo,
        "--title", "🔐 Security: Remove pull_request_target from workflows",
        "--label", "security,prt-violation",
        "--body", body
    ])
    print(f"    ✅ Issue created in {repo}")


def upsert_central_issue(org_name, violations, security_team):
    """
    Create or update the central governance dashboard issue for an org.
    Uses per-org label for deduplication.
    """
    if not violations:
        return

    scan_time  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    table_rows = "\n".join(
        [f"| `{v['repo']}` | `{v['files']}` |" for v in violations]
    )

    body = f"""## 🚨 `pull_request_target` Violations — `{org_name}`

**Scan time:** {scan_time}
**Total violations:** {len(violations)}

| Repository | Workflow Files |
|---|---|
{table_rows}

### Next Steps
- Each repo above has been automatically notified via a GitHub issue
- Repo maintainers should replace `pull_request_target` with `pull_request`
- Issues will auto-close once the violation is resolved and re-scanned

cc: @{security_team}"""

    # Use org-specific label for deduplication
    org_label = f"prt-{org_name}"
    existing  = issue_exists(GOVERNANCE_REPO, f"prt-violation,{org_label}")

    if existing:
        run_gh([
            "issue", "edit", existing,
            "--repo", GOVERNANCE_REPO,
            "--body", body
        ])
        run_gh([
            "issue", "comment", existing,
            "--repo", GOVERNANCE_REPO,
            "--body", f"♻️ Re-scanned {scan_time} — **{len(violations)}** violation(s) still open"
        ])
        print(f"  📝 Updated central dashboard issue #{existing} for {org_name}")
    else:
        run_gh([
            "issue", "create",
            "--repo", GOVERNANCE_REPO,
            "--title", f"🚨 [{org_name}] pull_request_target violations — {scan_time}",
            "--label", f"security,prt-violation,{org_label}",
            "--body", body
        ])
        print(f"  ✅ Central dashboard issue created for {org_name}")


# ══════════════════════════════════════════════════════════════════════════════
# SCAN MODES
# ══════════════════════════════════════════════════════════════════════════════

def scan_single_repo(repo_full_name, orgs_config):
    """
    Mode 3: Scan exactly one repo.
    Infers org config from orgs.yml if available, falls back to defaults.
    """
    if "/" not in repo_full_name:
        print(f"❌ repo_filter must be in format: org-name/repo-name")
        print(f"   Got: '{repo_full_name}'")
        sys.exit(1)

    org_name, _ = repo_full_name.split("/", 1)

    # Try to find org config for security_team info
    org_config    = next((o for o in orgs_config if o["name"] == org_name), {})
    security_team = org_config.get("security_team")

    print(f"\n{'='*60}")
    print(f"🔍 Single repo scan: {repo_full_name}")
    print(f"{'='*60}")

    files = search_prt_in_repo(repo_full_name)

    if files:
        files_str = ", ".join(files)
        print(f"  ⚠️  FOUND: {files_str}")
        create_repo_issue(repo_full_name, files_str, security_team)
        upsert_central_issue(
            org_name,
            [{"repo": repo_full_name, "files": files_str}],
            security_team
        )
        return {org_name: [{"repo": repo_full_name, "files": files_str}]}
    else:
        print(f"  ✅ No pull_request_target found in {repo_full_name}")
        return {org_name: []}


def scan_org(org_config):
    """
    Mode 2 / inner loop for Mode 1:
    Scan all repos in a single org, in chunks.
    Returns list of violation dicts.
    """
    org_name      = org_config["name"]
    visibility    = org_config.get("visibility", "public")
    security_team = org_config.get("security_team")

    print(f"\n{'='*60}")
    print(f"🔍 Scanning org: {org_name}  (visibility: {visibility})")
    print(f"{'='*60}")

    repos = list_repos(org_name, visibility)
    print(f"  📦 Total repos to scan: {len(repos)}")

    if not repos:
        print(f"  ℹ️  No repos found for {org_name} with visibility={visibility}")
        return []

    org_violations = []
    chunks         = [repos[i:i+CHUNK_SIZE] for i in range(0, len(repos), CHUNK_SIZE)]

    for chunk_idx, chunk in enumerate(chunks):
        print(f"\n  ── Chunk {chunk_idx + 1}/{len(chunks)} ({len(chunk)} repos) ──")

        for repo in chunk:
            print(f"    Checking {repo} ...", end=" ", flush=True)
            files = search_prt_in_repo(repo)

            if files:
                files_str = ", ".join(files)
                print(f"⚠️  {files_str}")
                org_violations.append({"repo": repo, "files": files_str})
                create_repo_issue(repo, files_str, security_team)
            else:
                print("✅")

        # Pause between chunks (except after the last one)
        if chunk_idx < len(chunks) - 1:
            print(f"\n  ⏳ Pausing {CHUNK_PAUSE}s between chunks ...")
            time.sleep(CHUNK_PAUSE)

    # Update central dashboard for this org
    upsert_central_issue(org_name, org_violations, security_team)

    return org_violations


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    if not TOKEN:
        print("❌ GH_TOKEN environment variable is not set.")
        sys.exit(1)

    # Load org configuration
    config_path = os.path.join(os.path.dirname(__file__), "..", "orgs.yml")
    with open(config_path) as f:
        config = yaml.safe_load(f)

    orgs_config = config.get("organizations", [])

    if not orgs_config:
        print("❌ No organizations found in orgs.yml")
        sys.exit(1)

    all_violations = {}

    # ── MODE 3: Single repo ───────────────────────────────────────────────
    if REPO_FILTER:
        # If both org_filter and repo_filter are set, validate they match
        if ORG_FILTER and not REPO_FILTER.startswith(f"{ORG_FILTER}/"):
            print(f"❌ repo_filter '{REPO_FILTER}' does not belong to org '{ORG_FILTER}'")
            sys.exit(1)

        all_violations = scan_single_repo(REPO_FILTER, orgs_config)

    # ── MODE 2: Single org ────────────────────────────────────────────────
    elif ORG_FILTER:
        org_config = next((o for o in orgs_config if o["name"] == ORG_FILTER), None)

        if not org_config:
            print(f"❌ Org '{ORG_FILTER}' not found in orgs.yml")
            print(f"   Available orgs: {[o['name'] for o in orgs_config]}")
            sys.exit(1)

        violations = scan_org(org_config)
        all_violations[ORG_FILTER] = violations

    # ── MODE 1: Full scan — all orgs ──────────────────────────────────────
    else:
        print(f"  📋 Orgs to scan: {len(orgs_config)}")
        for org_config in orgs_config:
            violations = scan_org(org_config)
            all_violations[org_config["name"]] = violations

    # ── SUMMARY ───────────────────────────────────────────────────────────
    print(f"""
{'='*60}
📊 SCAN COMPLETE — SUMMARY
{'='*60}""")

    total_violations = 0
    for org_name, violations in all_violations.items():
        count  = len(violations)
        status = f"⚠️  {count} violation(s)" if violations else "✅ Clean"
        print(f"  {org_name:<40} {status}")
        total_violations += count

    print(f"\n  Total violations found : {total_violations}")
    print(f"  Central dashboard      : https://github.com/{GOVERNANCE_REPO}/issues?q=label:prt-violation+state:open")

    if total_violations > 0:
        sys.exit(2)   # Non-zero exit so GitHub Actions marks the step as failed/warning


if __name__ == "__main__":
    main()