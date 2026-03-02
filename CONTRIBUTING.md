# Contributing to PenPard

First off, thank you for considering contributing to PenPard! Every contribution helps make AI-powered pentesting more accessible to the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Pull Request Process](#pull-request-process)
- [Style Guide](#style-guide)

## Code of Conduct

This project follows a simple rule: **be respectful and constructive**. We're all here to build better security tools. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## How Can I Contribute?

### Reporting Bugs

- Use the [GitHub Issues](https://github.com/penpard/penpard/issues) tab
- Include your OS, Node.js version, and Burp Suite version
- Provide steps to reproduce the issue
- Include console logs or error messages if available

### Suggesting Features

- Open a [GitHub Discussion](https://github.com/penpard/penpard/discussions) or Issue
- Describe the use case and expected behavior
- If it's a new vulnerability check, include references (CVE, CWE, etc.)

### Code Contributions

Areas where we especially need help:

| Area | Description |
|------|-------------|
| **Vulnerability Detection** | New attack strategies, payloads, and detection logic |
| **LLM Providers** | Support for additional LLM APIs (Cohere, Mistral API, etc.) |
| **Burp Extension** | New MCP tools, better proxy integration |
| **Mobile Scanning** | Improved MobSF integration, iOS support |
| **UI/UX** | Dashboard improvements, better visualization |
| **Documentation** | Tutorials, guides, API docs |
| **Testing** | Unit tests, integration tests, E2E tests |
| **Translations** | i18n support for the frontend |

## Development Setup

### Prerequisites

- Node.js 18+
- npm 9+
- Burp Suite Professional (for full testing)
- An LLM API key (or Ollama for local models)

### Installation

```bash
git clone https://github.com/penpard/penpard.git
cd penpard
npm install
```

### Running in Development

```bash
# Backend + Frontend (web mode)
npm run dev

# With Electron
npm run dev:electron
```

### Building

```bash
# Full production build
npm run build

# Platform-specific installers
npm run pack:win    # Windows
npm run pack:mac    # macOS
npm run pack:linux  # Linux
```

## Project Structure

```
penpard/
├── frontend/          # Next.js 14 frontend (React, Tailwind CSS)
├── backend/           # Express.js API server (TypeScript)
│   ├── agents/        # AI scanning agents
│   ├── services/      # Core services (LLM, Burp MCP, etc.)
│   └── routes/        # REST API endpoints
├── electron/          # Electron main process
├── burp-extension/    # Burp Suite MCP extension (Kotlin)
└── scripts/           # Build and utility scripts
```

### Key Files

| File | Purpose |
|------|---------|
| `backend/src/agents/OrchestratorAgent.ts` | Main AI scanning agent |
| `backend/src/services/LLMProviderService.ts` | Multi-provider LLM integration |
| `backend/src/services/burp-mcp.ts` | Burp Suite MCP client |
| `frontend/src/app/scan/[id]/MissionControlClient.tsx` | Live scan dashboard |
| `burp-extension/src/.../McpServer.kt` | MCP server in Burp |
| `electron/main.ts` | Electron main process |

## Pull Request Process

1. **Fork** the repo and create your branch from `main`
2. **Write** clear commit messages describing the change
3. **Test** your changes locally (both dev and production build)
4. **Update** documentation if you've changed APIs or added features
5. **Submit** the PR with a clear description of what and why

### PR Checklist

- [ ] Code compiles without errors (`npm run build`)
- [ ] No new linter warnings
- [ ] Tested in development mode
- [ ] Updated relevant documentation
- [ ] Updated CONTRIBUTING.md if process has changed

## Style Guide

### TypeScript

- Use TypeScript strict mode
- Prefer `const` over `let`
- Use async/await over raw promises
- Add types for function parameters and return values

### Frontend

- Use functional components with hooks
- State management with Zustand
- Styling with Tailwind CSS utility classes
- Use `lucide-react` for icons

### Backend

- Express.js routes with proper error handling
- Authentication middleware on protected routes
- Use `winston` logger (not `console.log`)
- SQLite via `better-sqlite3` (synchronous API)

### Commit Messages

```
feat: add SSRF detection to OrchestratorAgent
fix: resolve scan page navigation in Electron build
docs: update LLM provider configuration guide
refactor: extract payload generation into separate service
```

### AI-Assisted Contributions

This project was built with the help of AI coding tools, and we welcome AI-assisted contributions as well. Whether you write code entirely by hand or use AI tools like Copilot, Cursor, or ChatGPT — it's all welcome. What matters is:

- The code works correctly and passes review
- You understand the code you're submitting
- You've tested the changes locally

Please don't submit AI-generated code without reviewing and testing it first.

---

## 1) CLA required

By submitting a pull request, you agree to the terms in `CLA.md`.
We require CLA acceptance for all contributions.

## 2) Licensing compatibility

Contributions must be compatible with this repository's licensing model:
- Default license: PolyForm Noncommercial 1.0.0 (`LICENSE`)
- Commercial licensing rights: granted to the Maintainers via the CLA

## 3) Security

Do not report security vulnerabilities via public GitHub issues.
Please report them to: security@penpard.com

## 4) Contact

Commercial licensing: licensing@penpard.com  
General: info@penpard.com

## 5) Contribution guidelines

- Keep PRs small and focused
- Ensure tests and linters pass
- Provide clear descriptions and screenshots for UI changes

---

Thank you for contributing to PenPard! Together we're making security testing smarter and more accessible.

---

## Data Sanitization

> **Critical — read before your first commit.**

### Never include in a PR

| Category | Examples |
|---|---|
| Pentest reports | `*.pdf`, `*.docx`, `*.doc` |
| Network captures | `*.har`, `*.pcap`, `*.pcapng` |
| Real target lists | Real FQDNs, IPs, customer / company domains |
| Credentials / tokens | API keys, JWTs, cookies, secrets, passwords |
| Private keys / certs | `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| Uploaded user files | `backend/uploads/**` |
| Runtime logs | `backend/logs/**` |
| Database files | `*.sqlite`, `*.db` |
| Environment secrets | `.env`, `.env.production`, `.env.staging` |

The `.gitignore` excludes all of the above. The pre-commit hook blocks accidental commits.

### Install the pre-commit hook

```bash
# All platforms — preferred approach
git config core.hooksPath .githooks

# Linux/macOS only — make executable
chmod +x .githooks/pre-commit
```

### Use safe placeholder data in all tests, fixtures, and comments

**Domains (RFC 2606 — permanently reserved, never route to real hosts):**
```
example.com  |  test.example.org  |  api.example.net
```

**IP ranges (RFC 5737 — documentation-only, never routed):**
```
192.0.2.0/24     TEST-NET-1
198.51.100.0/24  TEST-NET-2
203.0.113.0/24   TEST-NET-3
```

**Example safe target list fixture:**
```
https://example.com
https://api.example.net/actuator/heapdump
192.0.2.1
198.51.100.42:8080/login
```

Real company or customer domains — even in comments or self-tests — must not appear in the codebase. Replace any real domain references with `example.com`.

### Updated PR Checklist

- [ ] `npx tsc --noEmit` passes on `backend/` and `frontend/`
- [ ] No real domains, IPs, API keys, or tokens in the diff
- [ ] No `*.pdf`, `*.docx`, `*.har`, `*.sqlite`, or `*.env` files staged
- [ ] All text (comments, logs, UI strings) is in English
- [ ] Pre-commit hook passed without warnings
- [ ] Safe fixtures (RFC 2606/5737) used for any sample data

