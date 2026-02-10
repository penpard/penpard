<p align="center">
  <img src="docs/banner.png" alt="PenPard Banner" width="800" />
</p>

<h1 align="center">PenPard — AI-Powered Penetration Testing Assistant</h1>

<p align="center">
  <strong>Your AI co-pilot for web and mobile security testing.</strong><br/>
  Autonomous LLM agents + Burp Suite integration + real-time vulnerability discovery.
  Cannot replace pentesters!
</p>

<p align="center">
  <a href="https://github.com/penpard/penpard/releases"><img src="https://img.shields.io/github/v/release/penpard/penpard?style=flat-square&color=00f0ff" alt="Release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="License" /></a>
  <a href="https://github.com/penpard/penpard/stargazers"><img src="https://img.shields.io/github/stars/penpard/penpard?style=flat-square&color=yellow" alt="Stars" /></a>
  <a href="https://github.com/penpard/penpard/issues"><img src="https://img.shields.io/github/issues/penpard/penpard?style=flat-square" alt="Issues" /></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square" alt="Platform" />
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-how-it-works">How It Works</a> •
  <a href="#-supported-llm-providers">LLM Providers</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## What is PenPard?

PenPard is an **open-source, AI-driven penetration testing desktop application** that uses Large Language Models to autonomously plan, execute, and report security assessments. It integrates directly with **Burp Suite Professional** through a custom MCP (Model Context Protocol) extension, giving AI agents full control over HTTP requests, scanning, and traffic analysis.

Think of it as an **AI pentester** that works alongside you — it can scan autonomously, or pause and assist you during manual testing.

**PenPard runs entirely on your machine. No data leaves your network.**

---

### The Problem with Current AI Security Tools

AI is transforming cybersecurity, but today's tools come with serious trade-offs:

#### 1. Commercial AI Pentest Platforms Are Prohibitively Expensive

| Tool | Pricing | Model |
|------|---------|-------|
| Pentera | $100,000+ / year | SaaS, closed source |
| Horizon3.ai NodeZero | Enterprise pricing (custom quote) | Cloud-only |
| XM Cyber | $50,000+ / year | SaaS |
| Cobalt Strike + AI modules | $5,000+ / year per user | Licensed |

Most teams — especially startups, independent researchers, and smaller security firms — simply can't afford these. PenPard costs **$0** and gives you full access to the source code.

#### 2. "AI Pentest" Often Means "ChatGPT Wrapper"

Many tools market themselves as AI-powered but are just thin wrappers around GPT:

- **They can't actually test anything.** They generate suggestions, not real HTTP requests. You still do all the work.
- **No tool integration.** They don't connect to Burp Suite, don't have access to proxy traffic, and can't interact with the target application.
- **Hallucinated vulnerabilities.** Without actual verification, LLMs confidently report vulnerabilities that don't exist. Studies show GPT-4 produces false positives in **60-80%** of security assessments when used without execution capabilities.

PenPard's agents don't just *think* about attacks — they **execute them** through Burp Suite, analyze real responses, and validate findings with a dedicated Recheck Agent.

#### 3. SaaS Tools Mean Your Data Leaves Your Network

Cloud-based security platforms require you to expose your target application or send scan data to external servers. For enterprises, regulated industries, or bug bounty hunters working under NDA, this is a dealbreaker.

**PenPard runs 100% locally.** Your targets, findings, LLM prompts, and reports never leave your machine.

#### 4. Black-Box AI Gives You No Visibility

Most AI security tools operate as a black box: you press "Scan" and get a report. You have no idea what the AI tested, what it missed, or why it made certain decisions.

PenPard gives you **full transparency**:
- Watch every agent decision in real-time logs
- Read the exact prompts sent to the LLM
- Interact with the agent mid-scan via chat
- Pause the scan, test manually, and let the AI assist you
- Customize system prompts and testing strategies

---

### Why PenPard?

| Traditional Scanners | PenPard |
|---|---|
| Static rule-based checks | LLM-driven reasoning and adaptation |
| Fixed payload lists | Context-aware payload generation |
| Isolated scan results | Interactive chat with the AI agent during scans |
| No learning between tests | Shared context between parallel agents |
| One-size-fits-all | Custom prompts and testing strategies |

---

## ✨ Features

### AI-Powered Scanning
- **Orchestrator Agent** — LLM-driven scan lifecycle: reconnaissance, planning, testing, reporting
- **Agent Pool** — Parallel scanning with specialized workers (crawler, scanner, fuzzer, analyzer)
- **Recheck Agent** — Validates findings with additional payloads to reduce false positives
- **Smart Assist** — Detects your manual testing patterns and offers to help automatically

### Burp Suite Integration
- **Samaritan MCP Connect** — Custom Burp extension providing 20+ tools via Model Context Protocol
- Full proxy history access, site map, scanner, repeater, intruder integration
- AI agents craft and send HTTP requests through Burp's proxy engine
- Real-time activity monitoring of your Burp traffic

### Multi-Provider LLM Support
- **OpenAI** (GPT-4o, GPT-4.1, GPT-5.1, o-series)
- **Azure OpenAI** (enterprise deployments)
- **Anthropic** (Claude 4 Sonnet/Opus)
- **Google Gemini** (2.5 Pro/Flash)
- **DeepSeek** (V3, R1)
- **Ollama** (any local model — Llama, Mistral, CodeLlama, etc.)

### Desktop Application
- **Cross-platform** — Windows, macOS, Linux (Electron)
- **Custom titlebar** with integrated menu system
- **Mission Control** — Real-time scan dashboard with live logs, findings, and AI chat
- **Token usage tracking** — Monitor LLM costs by model, provider, and month
- **Auto-updater** — Seamless updates from your configured update server

### Security Testing Capabilities
- OWASP Top 10 coverage (SQLi, XSS, SSRF, IDOR, etc.)
- Authentication and authorization testing
- Parameter fuzzing with AI-generated payloads
- Comprehensive PDF reports with CVSS 4.0 scores
- Mobile app analysis via MobSF integration

### Pause & Assist Workflow
- Pause the autonomous scan at any time
- Manually test in Burp while PenPard monitors your traffic
- PenPard detects what you're testing (SQLi? XSS? LFI?) and offers focused assistance
- Accept the suggestion → PenPard runs a targeted automated scan on that endpoint

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ and **npm**
- **Burp Suite Professional** with the Samaritan MCP Connect extension loaded
- An **LLM API key** (OpenAI, Anthropic, Gemini, or a local Ollama instance)

### Installation

```bash
# Clone the repository
git clone https://github.com/penpard/penpard.git
cd penpard

# Install all dependencies (root + frontend + backend)
npm install

# Configure environment
cp .env.example .env
# Edit .env with your API keys and settings
```

### Development Mode

```bash
# Start backend + frontend concurrently
npm run dev

# Or start with Electron
npm run dev:electron
```

### Production Build

```bash
# Windows
npm run pack:win

# macOS
npm run pack:mac

# Linux
npm run pack:linux
```

### Burp Extension Setup

1. Build the extension:
   ```bash
   cd burp-extension
   ./gradlew build
   ```
2. In Burp Suite → Extensions → Add → Select the built JAR file
3. The MCP server starts automatically on port `9876`
4. Configure the port and settings in the "Samaritan" tab in Burp

### Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `securepass` | Super Admin |

> **Change the default password immediately** in Settings → Account Security.

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Electron Shell                           │
│  ┌──────────────────────────┐  ┌─────────────────────────────┐  │
│  │     Next.js Frontend     │  │     Express.js Backend      │  │
│  │                          │  │                             │  │
│  │  Dashboard               │  │  ┌─ OrchestratorAgent ───┐  │  │
│  │  Mission Control         │  │  │  Planning → Testing    │  │  │
│  │  Settings / LLM Config   │  │  │  → Reporting           │  │  │
│  │  Reports                 │  │  └────────────────────────┘  │  │
│  │  Token Usage             │  │  ┌─ AgentPool ───────────┐  │  │
│  │                          │  │  │  Crawler Workers       │  │  │
│  │  Smart Suggestion Alert  │  │  │  Scanner Workers       │  │  │
│  │                          │  │  │  Fuzzer Workers        │  │  │
│  └──────────┬───────────────┘  │  │  Analyzer Workers      │  │  │
│             │ REST API          │  └────────────────────────┘  │  │
│             └───────────────────┤                             │  │
│                                 │  LLMProviderService         │  │
│                                 │  ActivityMonitorService     │  │
│                                 │  BurpMCPClient              │  │
│                                 │  ReportService              │  │
│                                 └──────────┬──────────────────┘  │
└────────────────────────────────────────────┼─────────────────────┘
                                             │ MCP (JSON-RPC)
                                             ▼
                              ┌──────────────────────────────┐
                              │  Burp Suite Professional      │
                              │  + Samaritan MCP Connect      │
                              │                              │
                              │  Proxy · Scanner · Repeater  │
                              │  Intruder · Site Map         │
                              └──────────────────────────────┘
                                             │
                                             ▼
                                      Target Application
```

### Project Structure

```
penpard/
├── frontend/                 # Next.js 14 (App Router, static export)
│   └── src/
│       ├── app/              # Pages (dashboard, scan, settings, reports...)
│       ├── components/       # UI components
│       ├── lib/store/        # Zustand state management
│       └── styles/           # Tailwind CSS
├── backend/                  # Express.js API server
│   └── src/
│       ├── agents/           # AI agents (Orchestrator, Pool, Workers, Recheck)
│       ├── services/         # LLM, Burp MCP, Activity Monitor, Reports
│       ├── routes/           # REST API endpoints
│       ├── db/               # SQLite schema & init
│       └── middleware/       # JWT auth
├── electron/                 # Desktop wrapper (main, preload, updater)
├── burp-extension/           # Samaritan MCP Connect (Kotlin/Gradle)
├── licensing/                # Optional license server
├── vulnerable-app/           # Intentionally vulnerable test app (Flask)
├── scripts/                  # Build helpers
└── docs/                     # Documentation
```

---

## 🔄 How It Works

### Autonomous Scan Flow

```
1. User configures target URL and scan options
2. OrchestratorAgent initializes with LLM context
3. PLANNING phase — LLM analyzes target, creates attack plan
4. RECONNAISSANCE — Crawls site via Burp, discovers endpoints
5. TESTING — Iterates over endpoints:
   ├── Generates context-aware payloads (SQLi, XSS, SSRF, etc.)
   ├── Sends requests through Burp MCP
   ├── Analyzes responses with LLM
   ├── RecheckAgent validates suspected findings
   └── Saves confirmed vulnerabilities
6. REPORTING — Generates PDF report with CVSS 4.0 scores
```

### Pause & Assist Flow

```
1. User pauses the scan → Agent loop suspends (stays alive)
2. Activity Monitor auto-starts → Watches Burp proxy history
3. User tests manually in Burp (e.g., tries SQLi payloads)
4. Monitor detects the pattern → Shows "SQL Injection Testing Detected" alert
5. User clicks "Assist" → Focused scan on that endpoint
6. User clicks "Resume" → Main scan continues from where it left off
```

### Mission Control

The real-time scan dashboard shows:
- **Live agent logs** — Every decision the AI makes
- **Vulnerability findings** — Discovered in real-time with severity badges
- **Interactive chat** — Send commands to the agent mid-scan
- **Pause/Resume controls** — Take over when you want to
- **Progress tracking** — Phase-by-phase scan progress

---

## 🤖 Supported LLM Providers

| Provider | Models | Configuration |
|----------|--------|---------------|
| **OpenAI** | GPT-4o, GPT-4.1, GPT-5.1, o1, o3, o4-mini | API Key |
| **Azure OpenAI** | Any deployed model | Endpoint URL + Deployment Name + API Key |
| **Anthropic** | Claude 4 Sonnet, Claude 4 Opus | API Key |
| **Google Gemini** | Gemini 2.5 Pro, Gemini 2.5 Flash | API Key |
| **DeepSeek** | DeepSeek V3, DeepSeek R1 | API Key |
| **Ollama** | Llama 3, Mistral, CodeLlama, Qwen, any GGUF | Local (no key needed) |

Configure providers in **Settings → LLM Configuration**. PenPard supports setting custom base URLs for OpenAI-compatible APIs.

---

## 🔧 Burp Extension — Samaritan MCP Connect

The custom Burp Suite extension exposes 20+ tools via the Model Context Protocol:

| Category | Tools |
|----------|-------|
| **HTTP** | `send_http_request`, `get_proxy_history`, `get_sitemap` |
| **Scanning** | `send_to_scanner`, `get_scanner_issues`, `spider_url` |
| **Testing** | `send_to_repeater`, `send_to_intruder`, `check_authorization` |
| **Scope** | `add_to_scope`, `get_scope` |
| **Encoding** | `url_encode`, `url_decode`, `base64_encode`, `base64_decode`, `hash_data` |
| **Analysis** | `extract_links`, `extract_comments`, `generate_payloads` |
| **Control** | `enable_intercept`, `disable_intercept`, `get_burp_version` |
| **Monitor** | `get_user_activity` |

### Building the Extension

```bash
cd burp-extension
./gradlew build
# Output: build/libs/samaritan-mcp-connect-*.jar
```

---

## 📊 Token Usage Tracking

PenPard tracks every LLM API call locally:

- **Per-call logging** — Provider, model, input/output tokens, context
- **Dashboard widget** — Total tokens used at a glance
- **Detailed analytics page** — Filter by month, group by model
- **Daily breakdown chart** — Input vs output token distribution
- **All data stays local** — Stored in SQLite, never sent externally

---

## 🛡 Security

- **JWT authentication** with bcrypt password hashing
- **Role-based access control** (Super Admin, Admin, User)
- **Auth guards** on all sensitive routes
- **CORS protection** with strict origin whitelist
- **Helmet security headers**
- **Rate limiting** on authentication endpoints
- **All data stored locally** — SQLite database, no cloud dependencies

---

## 🖥 Tech Stack

| Layer | Technology |
|-------|------------|
| **Desktop** | Electron 28, TypeScript |
| **Frontend** | Next.js 14, React 18, Tailwind CSS, Framer Motion, Zustand |
| **Backend** | Express.js, TypeScript, better-sqlite3 |
| **AI** | OpenAI SDK, Anthropic SDK, Google Generative AI, Ollama |
| **Burp Extension** | Kotlin, Burp Montoya API, NanoHTTPD |
| **Reports** | pdf-lib, Puppeteer |
| **Build** | electron-builder, cross-env |

---

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas We Need Help With

- New vulnerability detection strategies and payloads
- Support for additional LLM providers
- Burp extension improvements (new MCP tools)
- Mobile scanning enhancements
- UI/UX improvements
- Documentation and tutorials
- Translations

### Development Setup

```bash
# Clone and install
git clone https://github.com/penpard/penpard.git
cd penpard
npm install

# Start in development mode
npm run dev

# Frontend: http://localhost:3000
# Backend:  http://localhost:4000
```

See [CURSOR_CONTINUE.MD](CURSOR_CONTINUE.MD) for the detailed development changelog.

---

## 📋 Roadmap

- [ ] **CI/CD Pipeline** — GitHub Actions for automated builds and releases
- [ ] **Docker Support** — One-command deployment with Docker Compose
- [ ] **Plugin System** — Custom scan modules and attack strategies
- [ ] **Team Collaboration** — Shared scans, findings, and reports
- [ ] **OWASP ZAP Integration** — Alternative to Burp Suite
- [ ] **API Scanning** — OpenAPI/Swagger-driven API testing
- [ ] **Cloud Deployments** — Test cloud infrastructure (AWS, Azure, GCP)
- [ ] **Nuclei Integration** — Community-driven vulnerability templates
- [ ] **More MCP Tools** — Authentication flows, WebSocket testing, GraphQL

---

## 📜 License

PenPard is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

This means you are free to use, modify, and distribute this software, as long as any derivative works are also distributed under the same license.

---

## ⚠️ Disclaimer

PenPard is designed for **authorized security testing only**. Always obtain proper authorization before testing any system. The developers assume no liability for misuse of this tool. Use responsibly and ethically.

---

<p align="center">
  <sub>Built with ❤️ by the PenPard Team</sub><br/>
  <sub>Star ⭐ the repo if you find it useful!</sub>
</p>
