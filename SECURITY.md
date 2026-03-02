# Security Policy

Do not report security vulnerabilities via public GitHub issues.

Please report security issues to:
security@penpard.com

Include:
- Steps to reproduce
- Impact
- Affected component and version
- Proof of concept if available

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in PenPard, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Email us at **security@penpard.com** with:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge your report within **48 hours**.
- **Assessment**: We will assess the vulnerability and determine its severity within **7 days**.
- **Fix**: Critical vulnerabilities will be patched as quickly as possible.
- **Disclosure**: We will coordinate with you on public disclosure timing.

### Scope

The following are in scope:

- PenPard backend API (Express.js)
- PenPard frontend (Next.js)
- PenPard Electron shell
- PenPard MCP Connect Burp extension
- Authentication and authorization mechanisms
- Data storage and handling

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report these to the respective projects)
- Social engineering attacks
- Denial of service attacks

### Default Credentials

PenPard uses a **lock screen** model. There are no traditional username/password login credentials.

| Item | Default Value | Change In |
|------|--------------|-----------|
| Lock Key | `penpard` | Settings → Lock Key |

The backend also creates an internal `operator` user (used for scan ownership). This user is not directly accessible via the lock screen UI.

**These defaults must be changed immediately after first use.** This is documented behavior, not a vulnerability.

## Security Best Practices for Users

1. **Change the default lock key** immediately after installation
2. **Set a strong `JWT_SECRET`** in your `.env` file (if not set, a random key is generated per restart)
3. **Set `CORS_ORIGINS`** in your `.env` if deploying beyond localhost
4. **Keep PenPard updated** to the latest version
5. **Only use PenPard for authorized security testing** — unauthorized testing is illegal
6. **Do not expose PenPard's backend port** (4000) to the public internet

## Acknowledgments

We appreciate the security research community's efforts in helping keep PenPard secure. Reporters of valid vulnerabilities will be acknowledged here (with permission).

---

## Data Handling Policy: What Must Never Be Committed

PenPard processes real pentest reports and sensitive engagement data. The following **must never be committed** to this repository:

| Category | Examples |
|---|---|
| Pentest reports | `*.pdf`, `*.docx`, `*.doc` |
| Network captures | `*.har`, `*.pcap`, `*.pcapng` |
| Real target lists | Files containing real FQDNs, IPs, customer domains |
| Credentials / tokens | API keys, JWTs, session cookies, passwords |
| Private keys / certs | `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| Uploaded user files | Anything under `backend/uploads/` |
| Runtime logs | Anything under `backend/logs/` |
| Database files | `*.sqlite`, `*.db` |
| Environment secrets | `.env`, `.env.production`, `.env.staging` |

All of the above are excluded by `.gitignore`.

### Pre-commit Protection

A pre-commit hook is bundled in `.githooks/` to block accidental commits.

**Install (recommended — applies to all clones):**
```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit   # Linux/macOS only
```

**Manual install:**
```bash
# Linux/macOS
cp .githooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
# Windows PowerShell
Copy-Item .githooks\pre-commit.ps1 .git\hooks\pre-commit.ps1
```

### Safe Fixtures for Tests and Documentation

Always use RFC-reserved domains and IPs in code, tests, and comments:

**Safe domains (RFC 2606):**
```
example.com  |  test.example.org  |  api.example.net
```

**Safe IP ranges (RFC 5737 — documentation-only, never routed):**
```
192.0.2.0/24   (TEST-NET-1)
198.51.100.0/24 (TEST-NET-2)
203.0.113.0/24  (TEST-NET-3)
```

### Removing Accidentally Committed Sensitive Files

```bash
# Install: pip install git-filter-repo

# Purge all PDF and DOCX files from full history
git filter-repo --path-glob '*.pdf' --invert-paths
git filter-repo --path-glob '*.docx' --invert-paths

# Force-push all branches and tags
git push origin --force --all
git push origin --force --tags
```

All collaborators must re-clone after a history rewrite:
```bash
git clone <repo-url>
```

**Alternate (BFG Repo Cleaner):**
```bash
java -jar bfg.jar --delete-files "*.{pdf,docx,har,pcap}" repo.git
cd repo.git && git reflog expire --expire=now --all && git gc --prune=now --aggressive
git push origin --force --all
```

