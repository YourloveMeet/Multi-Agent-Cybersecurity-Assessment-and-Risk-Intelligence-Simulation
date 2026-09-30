# Multi-Agent Cybersecurity Assessment and Risk Intelligence Platform
## Development Specification — Terminal / CLI First

> **Purpose:** This document is the complete implementation brief for a development agent.
>
> **Primary UX goal:** Build the entire product as a polished, interactive terminal application inspired by the workflow and feel of tools such as Claude Code and Codex CLI: persistent terminal session, clear status areas, live agent activity, structured findings, readable tables, and command-driven navigation.
>
> **Implementation constraint:** The project must be realistic to implement as a strong working MVP in a single development day. Prioritize a coherent, testable end-to-end pipeline over a large number of partially implemented features.

---

# 1. Product Definition

## 1.1 Product name

Use the working name:

**CyberSentinel**

Alternative internal package name:

```text
cybersentinel
```

The product is a **multi-agent defensive cybersecurity assessment and risk intelligence platform**.

The application accepts a target that the user is authorized to assess and coordinates multiple specialized agents to:

1. discover basic target information,
2. inspect common security configuration issues,
3. normalize findings,
4. calculate risk,
5. correlate technical findings with asset/business context,
6. prioritize remediation,
7. generate a final assessment report.

The entire interface is terminal-based.

---

# 2. Core Product Principle

Do NOT build this as a conventional web application.

There is:

- no React frontend,
- no browser dashboard,
- no Streamlit UI,
- no desktop GUI.

The terminal IS the frontend.

The application should feel like an advanced developer/security CLI rather than a collection of Python scripts.

Expected experience:

```text
$ cybersentinel assess example.com

╭──────────────────────────────────────────────────────────────╮
│ CYBERSENTINEL                                               │
│ Multi-Agent Cybersecurity Assessment & Risk Intelligence    │
╰──────────────────────────────────────────────────────────────╯

Target     example.com
Mode       Authorized Assessment
Profile    Standard
Started    19:42:11

AGENTS
  ◉ Orchestrator
  ○ Reconnaissance Agent
  ○ Web Security Agent
  ○ Configuration Agent
  ○ Risk Intelligence Agent
  ○ Report Agent

[19:42:12] Orchestrator  Creating assessment context...
[19:42:12] Recon Agent   Resolving target...
[19:42:13] Recon Agent   Target reachable
[19:42:13] Web Agent     Inspecting HTTP security headers...
...
```

Then the application should transition into an assessment summary:

```text
╭──────────────────── RISK SUMMARY ────────────────────────────╮
│ Overall Risk       HIGH                                      │
│ Risk Score         78 / 100                                 │
│ Critical           1                                         │
│ High               3                                         │
│ Medium             5                                         │
│ Low                2                                         │
╰──────────────────────────────────────────────────────────────╯
```

And allow interactive follow-up commands in the same session:

```text
cybersentinel> findings
cybersentinel> explain FIND-004
cybersentinel> prioritize
cybersentinel> assets
cybersentinel> report
cybersentinel> export json
cybersentinel> export markdown
cybersentinel> help
cybersentinel> exit
```

---

# 3. Scope

## 3.1 Required MVP

The MVP MUST contain:

- interactive terminal shell,
- assessment command,
- multi-agent orchestration,
- at least 4 specialized agents,
- structured agent outputs,
- finding aggregation,
- deterministic risk scoring,
- asset context,
- remediation recommendations,
- assessment summary,
- Markdown export,
- JSON export,
- demo/simulation mode,
- safe real inspection mode for authorized targets,
- error handling,
- logging,
- configuration file support,
- unit tests for core logic.

## 3.2 Optional enhancements

Only implement these after the complete MVP works:

- LLM-assisted finding explanation,
- interactive remediation workflow,
- historical comparison,
- SQLite persistence,
- assessment history command,
- colored severity trend,
- agent retry policy,
- concurrency for independent agents,
- terminal command autocomplete,
- theme configuration.

## 3.3 Explicitly out of scope

Do NOT build:

- exploit automation,
- credential theft,
- password cracking,
- malware generation,
- persistence mechanisms,
- destructive testing,
- denial-of-service behavior,
- stealth/evasion,
- payload delivery,
- arbitrary exploitation,
- a browser frontend,
- a complicated ML training pipeline.

The scanner should remain defensive and non-destructive.

---

# 4. Safety and Authorization Model

The tool is intended for defensive assessments.

The application must make authorization explicit.

Every assessment should carry:

```python
authorized: bool
```

The normal assessment command should require the user to explicitly confirm authorization before a real target inspection.

Example:

```text
Target: example.com

This assessment mode performs non-destructive security checks.
Only continue if you are authorized to assess this target.

Proceed? [y/N]
```

For demo mode, no authorization confirmation is necessary because no real target is contacted.

Real inspection should be limited to safe checks such as:

- DNS resolution,
- HTTP/HTTPS GET/HEAD requests,
- response-header inspection,
- cookie attribute inspection,
- TLS certificate inspection,
- safe TCP connection checks to a restricted configured port set,
- basic service availability.

Do not implement exploit payloads.

---

# 5. User Experience Requirements

## 5.1 Terminal framework

Preferred libraries:

```text
Typer
Rich
Pydantic
httpx or requests
dnspython
```

Optional:

```text
prompt_toolkit
```

Use standard Python wherever practical.

Recommended CLI architecture:

```text
Typer
  ├── top-level commands
  ├── command parsing
  └── non-interactive execution

Rich
  ├── panels
  ├── tables
  ├── progress indicators
  ├── live logs
  ├── Markdown rendering
  └── terminal formatting

Prompt Toolkit (optional)
  ├── persistent shell
  ├── history
  └── autocomplete
```

If `prompt_toolkit` adds unnecessary complexity, use a simple Rich + `input()` interactive loop.

---

# 6. CLI Design

## 6.1 Top-level command

The executable must be:

```bash
cybersentinel
```

It should support both one-shot and interactive usage.

Examples:

```bash
cybersentinel
cybersentinel assess example.com
cybersentinel assess example.com --profile standard
cybersentinel demo
cybersentinel history
cybersentinel config
cybersentinel version
cybersentinel help
```

---

# 7. Interactive Shell

When launched without a subcommand:

```bash
cybersentinel
```

open a persistent shell.

Example:

```text
╭──────────────────────────────────────────────────────────────╮
│ CyberSentinel v0.1                                           │
│ Type 'help' for commands.                                   │
╰──────────────────────────────────────────────────────────────╯

cybersentinel>
```

Supported commands:

```text
help
assess <target>
demo
status
agents
findings
assets
risk
explain <finding_id>
recommend <finding_id>
report
export json
export markdown
history
clear
version
exit
quit
```

The shell maintains the current assessment in memory.

Example:

```text
cybersentinel> assess example.com
```

After completion:

```text
cybersentinel> findings
```

must display findings from the active assessment.

---

# 8. One-Shot CLI Commands

## 8.1 Assessment

```bash
cybersentinel assess example.com
```

Options:

```bash
--profile standard
--profile quick
--demo
--json
--output PATH
--no-color
--verbose
```

Examples:

```bash
cybersentinel assess example.com --profile standard
cybersentinel assess example.com --demo
cybersentinel assess example.com --json --output reports/result.json
```

## 8.2 Demo mode

```bash
cybersentinel demo
```

Demo mode should run entirely from deterministic synthetic data.

This mode is essential because:

- internet access may be unavailable,
- real targets may reject requests,
- the project must always be demonstrable,
- classroom demonstrations should be predictable.

Demo mode should simulate:

- target discovery,
- open services,
- security header findings,
- configuration issues,
- asset classification,
- risk correlation.

---

# 9. Recommended Project Structure

Use this structure:

```text
cybersentinel/
│
├── pyproject.toml
├── README.md
├── DEVELOPMENT.md
├── requirements.txt
├── .gitignore
│
├── src/
│   └── cybersentinel/
│       │
│       ├── __init__.py
│       ├── __main__.py
│       │
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── app.py
│       │   ├── shell.py
│       │   ├── commands.py
│       │   └── rendering.py
│       │
│       ├── core/
│       │   ├── __init__.py
│       │   ├── orchestrator.py
│       │   ├── assessment.py
│       │   ├── event_bus.py
│       │   └── errors.py
│       │
│       ├── agents/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── recon.py
│       │   ├── web_security.py
│       │   ├── configuration.py
│       │   ├── risk_intelligence.py
│       │   └── report.py
│       │
│       ├── scanners/
│       │   ├── __init__.py
│       │   ├── dns.py
│       │   ├── http.py
│       │   ├── tls.py
│       │   └── ports.py
│       │
│       ├── risk/
│       │   ├── __init__.py
│       │   ├── scoring.py
│       │   ├── severity.py
│       │   ├── prioritization.py
│       │   └── rules.py
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── target.py
│       │   ├── asset.py
│       │   ├── finding.py
│       │   ├── assessment.py
│       │   └── events.py
│       │
│       ├── demo/
│       │   ├── __init__.py
│       │   ├── data.py
│       │   └── scenario.py
│       │
│       ├── reporting/
│       │   ├── __init__.py
│       │   ├── markdown.py
│       │   └── json_export.py
│       │
│       ├── storage/
│       │   ├── __init__.py
│       │   └── repository.py
│       │
│       ├── config/
│       │   ├── __init__.py
│       │   └── settings.py
│       │
│       └── utils/
│           ├── __init__.py
│           ├── ids.py
│           ├── timestamps.py
│           └── validation.py
│
├── tests/
│   ├── test_scoring.py
│   ├── test_aggregation.py
│   ├── test_models.py
│   ├── test_agents.py
│   └── test_demo.py
│
├── reports/
│
└── data/
    └── demo/
        └── standard_target.json
```

---

# 10. Architecture

The system should use the following flow:

```text
CLI
 │
 ▼
AssessmentContext
 │
 ▼
Orchestrator
 │
 ├── Reconnaissance Agent
 │       └── scanners
 │
 ├── Web Security Agent
 │       └── HTTP scanner
 │
 ├── Configuration Agent
 │       ├── TLS scanner
 │       └── service scanner
 │
 ▼
Finding Aggregator
 │
 ▼
Risk Intelligence Agent
 │
 ▼
Prioritization Engine
 │
 ▼
Report Agent
 │
 ├── Terminal summary
 ├── Markdown report
 └── JSON export
```

---

# 11. Agent Interface

Every agent should follow the same interface.

Create:

```python
class BaseAgent(ABC):
    name: str
    description: str

    @abstractmethod
    def run(self, context: AssessmentContext) -> AgentResult:
        ...
```

Every agent returns an `AgentResult`.

Example:

```python
class AgentResult(BaseModel):
    agent_name: str
    status: Literal["success", "partial", "failed"]
    duration_ms: int
    findings: list[Finding]
    assets: list[Asset]
    observations: list[str]
    errors: list[str]
    metadata: dict[str, Any]
```

Agents MUST NOT directly modify global state.

The orchestrator owns the assessment state.

---

# 12. Agent 1 — Reconnaissance Agent

## Purpose

Perform safe target discovery.

Responsibilities:

- validate target,
- normalize hostname,
- resolve DNS,
- determine basic reachability,
- inspect standard HTTP/HTTPS availability,
- identify configured ports,
- identify basic technologies only when easily observable.

Possible observations:

```text
DNS resolves
HTTPS available
HTTP available
Server header present
Redirects HTTP → HTTPS
Certificate found
```

Example output:

```json
{
  "agent_name": "reconnaissance",
  "status": "success",
  "observations": [
    "Target resolved successfully",
    "HTTPS endpoint is reachable"
  ]
}
```

Do not implement aggressive enumeration.

---

# 13. Agent 2 — Web Security Agent

## Purpose

Inspect common web security controls without exploitation.

Checks should include:

### Security headers

Look for:

```text
Strict-Transport-Security
Content-Security-Policy
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
```

### Cookie security

Inspect:

```text
Secure
HttpOnly
SameSite
```

### HTTPS behavior

Check:

- HTTPS reachable,
- HTTP redirect behavior,
- obvious mixed transport configuration.

### Information disclosure

Inspect headers such as:

```text
Server
X-Powered-By
```

Flag only when meaningful.

Each result becomes a standardized finding.

---

# 14. Agent 3 — Configuration Agent

## Purpose

Identify infrastructure/configuration weaknesses from safe observations.

Potential checks:

- TLS certificate validity,
- certificate expiry,
- protocol basics,
- selected service availability,
- unnecessary exposure in configured demo/test ports,
- HTTP service without redirect,
- administrative-service exposure in demo data.

Do not brute force ports.

Use a small safe default set, e.g.:

```python
DEFAULT_PORTS = [
    22,
    80,
    443,
    8080,
    8443
]
```

Allow configuration to change this set.

For real assessments, document that only authorized targets should be scanned.

---

# 15. Agent 4 — Risk Intelligence Agent

This is the core differentiator.

Its input is the normalized set of findings and assets.

It should:

1. remove duplicates,
2. correlate related findings,
3. calculate technical severity,
4. estimate business impact using asset criticality,
5. calculate a risk score,
6. assign remediation priority,
7. generate a concise rationale.

Example finding:

```text
Finding:
Missing HSTS

Technical Severity:
Medium

Asset Criticality:
High

Exposure:
External

Exploitability:
Moderate

Business Impact:
High

Risk Score:
72

Priority:
P1
```

---

# 16. Risk Model

Use deterministic scoring.

## 16.1 Inputs

Each finding contains:

```python
severity_score: int
exploitability_score: int
exposure_score: int
asset_criticality_score: int
confidence_score: int
```

Use a 1–10 scale.

Suggested formula:

```text
raw =
    severity_score
    * exploitability_score
    * exposure_score
    * asset_criticality_score
```

Normalize to 0–100.

Confidence can slightly adjust prioritization but should not overpower severity.

A simpler implementation is acceptable:

```text
risk =
(
    severity * 0.35
    + exploitability * 0.20
    + exposure * 0.20
    + asset_criticality * 0.25
) * 10
```

Clamp:

```text
0 <= risk <= 100
```

---

# 17. Risk Categories

Use:

```text
0–24    LOW
25–49   MODERATE
50–74   HIGH
75–100  CRITICAL
```

Do not use a score merely for visual effect. Every score should be explainable from its inputs.

---

# 18. Severity Model

Use:

```python
Severity = Enum(
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
)
```

Map to numeric values:

```text
INFO       = 1
LOW        = 2
MEDIUM     = 5
HIGH       = 8
CRITICAL   = 10
```

---

# 19. Finding Data Model

Create a Pydantic model similar to:

```python
class Finding(BaseModel):
    id: str
    title: str
    description: str
    category: str
    severity: Severity

    asset_id: str | None = None

    evidence: list[str] = []
    impact: str
    recommendation: str

    severity_score: int
    exploitability_score: int
    exposure_score: int
    asset_criticality_score: int
    confidence_score: int

    risk_score: float = 0.0
    priority: str = "P3"

    source_agent: str
    references: list[str] = []
```

Finding IDs should look like:

```text
FIND-001
FIND-002
FIND-003
```

---

# 20. Asset Data Model

Create:

```python
class Asset(BaseModel):
    id: str
    name: str
    asset_type: str

    host: str | None = None
    port: int | None = None

    exposure: str
    environment: str

    criticality: str
    criticality_score: int

    description: str | None = None
```

Example:

```json
{
  "id": "AST-001",
  "name": "Public Web Server",
  "asset_type": "web-server",
  "host": "example.com",
  "port": 443,
  "exposure": "internet",
  "environment": "production",
  "criticality": "high",
  "criticality_score": 8
}
```

---

# 21. Assessment Context

Create one central context object.

```python
class AssessmentContext(BaseModel):
    assessment_id: str
    target: Target
    authorized: bool
    mode: str
    profile: str

    assets: list[Asset]
    findings: list[Finding]

    observations: list[str]
    agent_results: list[AgentResult]

    started_at: datetime
    completed_at: datetime | None
```

---

# 22. Orchestrator

The orchestrator controls the complete lifecycle.

Pseudo-code:

```python
def run_assessment(context):

    emit("assessment.started")

    for agent in agents:
        emit("agent.started", agent.name)

        result = agent.run(context)

        context.agent_results.append(result)
        context.assets.extend(result.assets)
        context.findings.extend(result.findings)

        emit("agent.completed", agent.name, result.status)

    context.findings = aggregate_findings(
        context.findings
    )

    risk_result = risk_agent.run(context)

    context.findings = risk_result.findings

    report_result = report_agent.run(context)

    emit("assessment.completed")

    return context
```

---

# 23. Event System

The CLI should receive structured events rather than agents printing directly.

Create events like:

```text
assessment.started
assessment.completed

agent.started
agent.progress
agent.completed
agent.failed

finding.discovered
finding.updated

risk.calculated
report.generated
```

Event model:

```python
class AssessmentEvent(BaseModel):
    timestamp: datetime
    type: str
    agent: str | None = None
    message: str
    metadata: dict[str, Any] = {}
```

The renderer subscribes to these events.

This keeps security logic separate from terminal presentation.

---

# 24. Terminal Renderer

Use Rich extensively.

Required components:

## Header

```text
╭──────────────────────────────────────────────────────────────╮
│ CYBERSENTINEL                                                │
│ Multi-Agent Cybersecurity Assessment & Risk Intelligence    │
╰──────────────────────────────────────────────────────────────╯
```

## Agent panel

```text
AGENT PIPELINE

✓ Orchestrator           completed
✓ Reconnaissance         completed
✓ Web Security           completed
✓ Configuration          completed
✓ Risk Intelligence     completed
✓ Report                 completed
```

## Live activity

```text
[19:42:11] Recon Agent
  ├─ Resolving DNS
  ├─ Checking HTTPS
  └─ Building asset inventory
```

## Findings table

```text
ID        Finding                         Severity   Risk
FIND-001  Missing HSTS                   MEDIUM     72
FIND-002  Missing CSP                    HIGH       81
FIND-003  Server disclosure              LOW        31
```

## Risk summary

```text
OVERALL RISK: HIGH
RISK SCORE:   78/100
```

---

# 25. CLI Colors

Use severity-based terminal styling:

```text
INFO       dim
LOW        cyan/neutral
MEDIUM     yellow
HIGH       red
CRITICAL   bold red
```

Do not hardcode style names throughout the project.

Create a central theme mapping:

```python
SEVERITY_STYLES = {
    "INFO": "...",
    "LOW": "...",
    "MEDIUM": "...",
    "HIGH": "...",
    "CRITICAL": "..."
}
```

This makes the renderer maintainable.

---

# 26. Interactive Commands

## `status`

Show current assessment state:

```text
Target:
Mode:
Profile:
Started:
Status:
Agents completed:
Findings:
Risk:
```

## `agents`

Show each agent:

```text
Agent                     Status       Findings
-------------------------------------------------
Reconnaissance             COMPLETE        2
Web Security               COMPLETE        5
Configuration              COMPLETE        4
Risk Intelligence          COMPLETE        -
Report                     COMPLETE        -
```

## `findings`

Display all findings.

Support:

```text
findings
findings --severity HIGH
findings --priority P1
findings --agent web_security
```

## `explain`

Example:

```text
explain FIND-004
```

Output:

```text
FIND-004 — Missing Content-Security-Policy

WHY IT MATTERS
A CSP can reduce the impact of certain classes of browser-side attacks.

EVIDENCE
• CSP header was not observed in the response.

RISK
Technical severity: Medium
Exposure: Internet
Asset criticality: High
Risk score: 67

RECOMMENDATION
Define and deploy a restrictive CSP appropriate to the application.
```

The explanation must be derived from stored finding data.

---

# 27. `prioritize`

Sort by risk and remediation priority.

Example:

```text
REMEDIATION QUEUE

P0  FIND-009  Exposed administrative service
P1  FIND-004  Weak TLS configuration
P1  FIND-002  Missing CSP
P2  FIND-006  Missing HSTS
```

The project should document the meaning of each priority.

Suggested:

```text
P0 = immediate attention
P1 = high priority
P2 = planned remediation
P3 = low priority / hardening
```

---

# 28. Report Generation

The report must include:

```text
1. Executive Summary
2. Assessment Scope
3. Asset Inventory
4. Agent Summary
5. Findings
6. Risk Analysis
7. Remediation Priorities
8. Methodology
9. Limitations
10. Assessment Metadata
```

---

# 29. Markdown Report Format

Example:

```markdown
# CyberSentinel Security Assessment

## Executive Summary

Overall Risk: HIGH
Risk Score: 78/100

## Scope

Target: example.com
Mode: Authorized Assessment
Profile: Standard

## Agent Execution

| Agent | Status | Findings |
|---|---|---:|
| Reconnaissance | Complete | 2 |
| Web Security | Complete | 5 |
| Configuration | Complete | 4 |

## Findings

### FIND-001 — Missing HSTS

Severity: Medium
Risk Score: 72
Priority: P1

#### Evidence

- Strict-Transport-Security header was not observed.

#### Impact

...

#### Recommendation

...

## Remediation Priority

1. ...
2. ...
3. ...

## Limitations

This assessment uses non-destructive checks and does not establish exploitability.
```

---

# 30. JSON Output

Provide machine-readable output:

```json
{
  "assessment": {
    "id": "ASM-20260930-001",
    "target": "example.com",
    "mode": "authorized",
    "profile": "standard",
    "overall_risk": "HIGH",
    "risk_score": 78
  },
  "agents": [],
  "assets": [],
  "findings": [],
  "recommendations": []
}
```

This should be easy for another application to consume.

---

# 31. Demo Scenario

Create deterministic demo data.

Recommended scenario:

```text
Target:
acme-demo.local
```

Assets:

```text
AST-001  Public Web Server
AST-002  Authentication Service
AST-003  Admin Service
AST-004  API Server
```

Demo observations:

```text
HTTPS available
HTTP redirect incomplete
Missing HSTS
Missing CSP
Server header disclosed
TLS configuration needs hardening
Administrative service exposed
```

Generate approximately:

```text
1 Critical
3 High
5 Medium
2 Low
```

The exact count can be adjusted, but the demo should contain enough variation to make risk prioritization visually convincing.

---

# 32. Demo Agent Behavior

Demo mode should NOT fake terminal output by printing a static transcript.

It should run through the same real orchestrator and same agent interfaces using a `DemoScanner` or fixture layer.

Correct architecture:

```text
Demo Target
     ↓
Demo Scanner
     ↓
Real Agent Logic
     ↓
Real Aggregator
     ↓
Real Risk Engine
     ↓
Real Report Generator
```

This proves that the architecture itself works.

---

# 33. Scanner Abstraction

Create interfaces so demo and real sources can share the same agents.

Example:

```python
class NetworkScanner(Protocol):
    def resolve(self, host: str) -> ...
    def check_port(self, host: str, port: int) -> ...
```

Create implementations:

```text
RealNetworkScanner
DemoNetworkScanner
```

Likewise:

```text
RealHttpScanner
DemoHttpScanner
RealTlsScanner
DemoTlsScanner
```

This avoids duplicating the agent logic.

---

# 34. Error Handling

Errors must never crash the entire assessment unnecessarily.

For example:

```text
[19:42:31] Web Security Agent
  ! HTTPS request failed
  Continuing with available evidence...
```

The agent should return:

```python
status = "partial"
```

The orchestrator continues.

An assessment can finish with:

```text
Assessment completed with warnings.
```

rather than:

```text
Unhandled exception
```

---

# 35. Timeouts and Network Safety

For network operations:

- use short request timeouts,
- use TLS verification by default,
- never perform unlimited retries,
- never follow unbounded redirect loops,
- cap response body size when body content is not needed,
- avoid crawling,
- avoid recursive URL discovery.

The MVP should inspect a small set of endpoints only.

---

# 36. Configuration

Create:

```text
~/.cybersentinel/config.toml
```

Possible settings:

```toml
[scanner]
timeout = 5
verify_tls = true
max_redirects = 5

[assessment]
default_profile = "standard"
require_authorization = true

[output]
reports_dir = "./reports"
save_history = true
```

Provide:

```bash
cybersentinel config
```

to display active configuration.

---

# 37. Assessment Profiles

Implement:

## Quick

Only:

- DNS,
- reachability,
- HTTP headers,
- TLS certificate.

## Standard

Everything in Quick plus:

- cookie attributes,
- selected safe ports,
- configuration checks,
- risk intelligence.

Default:

```text
standard
```

---

# 38. Storage

For the one-day version, do NOT require a database.

Use JSON files:

```text
~/.cybersentinel/history/
```

Each assessment:

```text
ASM-20260930-001.json
ASM-20260930-002.json
```

Command:

```bash
cybersentinel history
```

should list:

```text
ID                   Target          Risk      Score
ASM-001              demo target     HIGH      78
ASM-002              example.com     MODERATE  46
```

SQLite can be added later.

---

# 39. Report Storage

Default:

```text
./reports/
```

Generate:

```text
assessment-ASM-001.md
assessment-ASM-001.json
```

Optional terminal command:

```text
export markdown
export json
```

---

# 40. Dependency Strategy

Keep dependencies minimal.

Expected dependencies:

```text
typer
rich
pydantic
httpx
dnspython
```

Optional:

```text
prompt-toolkit
tomli
```

Use the standard library wherever possible.

Avoid adding a dependency for something that can be implemented in approximately 20–30 lines of clean Python.

---

# 41. Testing Strategy

At minimum write tests for:

## Models

- valid finding,
- invalid finding,
- asset validation.

## Risk engine

Test:

```text
LOW
MODERATE
HIGH
CRITICAL
```

and boundary conditions.

## Aggregator

Ensure duplicate findings are merged.

## Demo

Ensure:

```text
demo -> orchestrator -> risk -> report
```

works end to end.

## CLI

Test:

```text
version
help
demo
```

at minimum.

---

# 42. Example Unit Test Targets

```python
def test_risk_score_is_bounded():
    score = calculate_risk(...)
    assert 0 <= score <= 100
```

```python
def test_duplicate_findings_are_merged():
    findings = [...]
    result = aggregate_findings(findings)
    assert len(result) == expected
```

```python
def test_demo_assessment_completes():
    result = run_demo_assessment()
    assert result.status == "completed"
    assert len(result.findings) > 0
```

---

# 43. Logging

Create two logging layers.

## User-facing event log

Pretty Rich output:

```text
[19:44:20] Web Agent
  Checking security headers...
```

## Debug log

Write to:

```text
~/.cybersentinel/cybersentinel.log
```

Use Python `logging`.

Do not dump secrets or sensitive request data.

---

# 44. AI / LLM Integration

LLM functionality must be optional.

The platform must work fully without an API key.

Create an abstraction:

```python
class IntelligenceProvider(Protocol):
    def explain_finding(self, finding: Finding) -> str:
        ...
```

Implement:

```text
RuleBasedIntelligenceProvider
OptionalLLMIntelligenceProvider
```

Default to:

```text
RuleBasedIntelligenceProvider
```

The optional LLM layer may improve:

- executive summaries,
- finding explanations,
- remediation wording.

It must not be required for the core risk score.

The deterministic scoring engine remains authoritative for the MVP.

---

# 45. Agent Communication Model

Agents communicate through structured models, NOT arbitrary text.

Bad:

```python
return "Found some security stuff"
```

Good:

```python
return AgentResult(
    agent_name="web_security",
    status="success",
    findings=[...],
    observations=[...],
    metadata={...}
)
```

This makes the system:

- testable,
- predictable,
- extensible,
- easy to explain in a presentation.

---

# 46. Avoid Fake Multi-Agent Architecture

Do not create five Python files that all call exactly the same function and merely change their names.

Each agent must have a distinct responsibility.

Required separation:

```text
Recon
    ↓
Discovery evidence

Web Security
    ↓
Application-layer configuration findings

Configuration
    ↓
TLS/service/configuration findings

Risk Intelligence
    ↓
Correlation + scoring + prioritization

Report
    ↓
Human-readable output
```

---

# 47. Concurrency

Do not optimize prematurely.

Once the sequential version works, independent scanning agents may be run concurrently with:

```python
asyncio.gather(...)
```

or a small thread pool.

Do this only if it remains simple.

Never sacrifice reliability for parallelism.

The demo should visibly show independent agents progressing.

---

# 48. Presentation Quality

The terminal UI must look professional.

Use:

- consistent spacing,
- clear headings,
- compact panels,
- readable tables,
- restrained colors,
- meaningful symbols,
- timestamps,
- progress states.

Avoid:

```text
HACKING!!!!!!!
CRITICAL BREACH!!!
```

Avoid sensational UI.

The platform is a professional security assessment tool.

---

# 49. Suggested Terminal Flow

When the program starts:

```text
╭──────────────────────────────────────────────────────────────╮
│ CYBERSENTINEL                                                │
│ Multi-Agent Cybersecurity Assessment & Risk Intelligence    │
│                                                              │
│ Type 'help' for commands.                                    │
╰──────────────────────────────────────────────────────────────╯
```

Then:

```text
cybersentinel> demo
```

Display:

```text
Assessment initialized.

Target:
acme-demo.local

Profile:
standard

Authorization:
simulation

Launching multi-agent assessment...
```

Agent execution:

```text
┌─ AGENT PIPELINE ─────────────────────────────────────────────┐
│ ✓ Orchestrator                                              │
│ ✓ Reconnaissance Agent                                      │
│ ◉ Web Security Agent                                        │
│ ○ Configuration Agent                                       │
│ ○ Risk Intelligence Agent                                   │
│ ○ Report Agent                                              │
└─────────────────────────────────────────────────────────────┘
```

Live events:

```text
[19:43:01] Recon Agent
  Resolving target...

[19:43:01] Recon Agent
  Discovered asset AST-001

[19:43:02] Web Security Agent
  Inspecting response headers...

[19:43:02] Web Security Agent
  Finding discovered: FIND-002

[19:43:03] Risk Intelligence
  Correlating findings...

[19:43:03] Risk Intelligence
  Overall risk calculated: HIGH
```

Final screen:

```text
╭──────────────────────── ASSESSMENT COMPLETE ────────────────╮
│ Target:        acme-demo.local                              │
│ Risk:          HIGH                                         │
│ Score:         78/100                                       │
│ Findings:      11                                           │
│ Duration:      2.8s                                         │
╰─────────────────────────────────────────────────────────────╯
```

Then:

```text
Top priorities:

P0  FIND-009  Exposed administrative service          91
P1  FIND-004  Weak TLS configuration                  82
P1  FIND-002  Missing Content Security Policy         77
P2  FIND-006  Missing HSTS                            61
```

---

# 50. Command Help

`help` should return a useful command tree:

```text
COMMANDS

Assessment
  assess <target>       Run authorized assessment
  demo                  Run deterministic demo

Analysis
  findings              Show findings
  assets                Show discovered assets
  risk                  Show risk summary
  prioritize            Show remediation order
  explain <id>          Explain a finding

Output
  report                Display report
  export markdown       Write Markdown report
  export json           Write JSON report

System
  agents                Show agent status
  status                Show current assessment
  history               Show previous assessments
  config                Show configuration
  version               Show version

Session
  clear                 Clear terminal
  exit                  Exit CyberSentinel
```

---

# 51. README Requirements

The project README must contain:

## Project title

```text
CyberSentinel
Multi-Agent Cybersecurity Assessment & Risk Intelligence Platform
```

## Problem statement

Explain why traditional basic scanners can produce large amounts of raw information without prioritizing business risk.

## Solution

Explain the multi-agent approach.

## Architecture

Include an ASCII architecture diagram.

## Features

List implemented features.

## Installation

Example:

```bash
git clone ...
cd cybersentinel
python -m venv .venv
```

Then platform-specific activation commands.

## Running

```bash
cybersentinel
cybersentinel demo
cybersentinel assess example.com
```

## Safety

Clearly state that real assessments require authorization.

## Demo

Show a terminal screenshot-style text example.

---

# 52. Development Order

The coding agent MUST work in this order.

## Step 1 — Scaffold

Create:

```text
pyproject.toml
src/
tests/
reports/
data/
```

Verify imports.

## Step 2 — Models

Implement:

```text
Target
Asset
Finding
AgentResult
AssessmentContext
AssessmentEvent
```

Write validation tests.

## Step 3 — Risk engine

Implement:

```text
severity mapping
risk formula
risk category
priority mapping
```

Write tests BEFORE moving on.

## Step 4 — Demo scanners

Implement:

```text
DemoDNSScanner
DemoHTTPScanner
DemoTLSScanner
DemoPortScanner
```

Return deterministic data.

## Step 5 — Agents

Implement:

```text
ReconAgent
WebSecurityAgent
ConfigurationAgent
RiskIntelligenceAgent
ReportAgent
```

Run them against demo scanners.

## Step 6 — Orchestrator

Connect all agents.

Verify full flow:

```text
demo
 -> context
 -> agents
 -> findings
 -> risk
 -> report
```

## Step 7 — Terminal renderer

Add Rich components.

Do NOT start with UI polish before core functionality works.

## Step 8 — Interactive shell

Add:

```text
help
demo
assess
findings
risk
explain
report
export
exit
```

## Step 9 — Real scanners

Only after demo mode works.

Implement safe:

```text
DNS
HTTP
TLS
restricted port connectivity
```

## Step 10 — Persistence

Add JSON assessment history.

## Step 11 — Testing

Run all tests and fix errors.

## Step 12 — Documentation

Complete README and development notes.

---

# 53. Definition of Done

The project is considered complete only when all of these work:

```bash
cybersentinel
```

opens interactive terminal.

```bash
cybersentinel demo
```

runs a complete multi-agent assessment.

```text
cybersentinel> findings
```

shows findings.

```text
cybersentinel> risk
```

shows calculated risk.

```text
cybersentinel> explain FIND-001
```

shows evidence, impact and recommendation.

```text
cybersentinel> prioritize
```

shows remediation order.

```text
cybersentinel> export markdown
```

writes a Markdown report.

```text
cybersentinel> export json
```

writes machine-readable output.

The program should recover gracefully from scanner failures.

At least one complete demo assessment should run without any internet connection.

---

# 54. Acceptance Test

The development agent should manually run:

```bash
python -m cybersentinel
```

Then:

```text
demo
```

Then:

```text
agents
```

Then:

```text
findings
```

Then:

```text
risk
```

Then:

```text
prioritize
```

Then:

```text
explain FIND-001
```

Then:

```text
report
```

Then:

```text
export markdown
```

Then:

```text
export json
```

Then:

```text
exit
```

All commands must work without restarting the application.

---

# 55. Quality Rules for the Coding Agent

The implementation agent MUST follow these rules.

### Rule 1

Prefer simple, working code over abstraction-heavy architecture.

### Rule 2

Keep the core domain independent from terminal rendering.

### Rule 3

Agents return structured results.

### Rule 4

No business logic inside CLI rendering functions.

### Rule 5

No network operations directly inside the Rich UI.

### Rule 6

Demo mode must use the same agent pipeline as real mode.

### Rule 7

Risk scoring must be deterministic.

### Rule 8

LLM integration must be optional.

### Rule 9

Do not add unnecessary dependencies.

### Rule 10

Do not implement offensive or destructive security functionality.

### Rule 11

Every major feature should be testable.

### Rule 12

Errors should produce actionable messages rather than stack traces by default.

### Rule 13

Debug mode may expose tracebacks.

### Rule 14

Use type hints throughout.

### Rule 15

Use docstrings on public classes and methods.

---

# 56. Suggested Internal Interfaces

## Agent

```python
class BaseAgent:
    name: str
    description: str

    def run(self, context: AssessmentContext) -> AgentResult:
        raise NotImplementedError
```

## Scanner

```python
class HTTPScanner(Protocol):
    def inspect(self, target: Target) -> HTTPObservation:
        ...
```

## Risk engine

```python
class RiskEngine:
    def calculate(
        self,
        finding: Finding,
        asset: Asset | None
    ) -> Finding:
        ...
```

## Report generator

```python
class MarkdownReportGenerator:
    def generate(
        self,
        context: AssessmentContext
    ) -> str:
        ...
```

---

# 57. Finding Deduplication

Different agents may report related issues.

Example:

```text
Web Security Agent:
Missing HSTS

Configuration Agent:
HTTPS hardening incomplete
```

The aggregator should identify duplicates or related findings using:

```text
normalized_title
category
asset_id
```

Do not merge findings merely because they share the same severity.

A simple normalized key is acceptable:

```python
key = (
    finding.category,
    finding.title.lower().strip(),
    finding.asset_id
)
```

---

# 58. Recommendations

Every non-informational finding must have a practical recommendation.

Example:

```text
Finding:
Missing X-Content-Type-Options

Recommendation:
Add the X-Content-Type-Options header with a value of nosniff where appropriate.
```

Recommendations should be short enough to show in a terminal.

Detailed explanation belongs in the report or `explain` command.

---

# 59. Limitations Section

The generated report must explicitly include limitations.

Example:

```text
This assessment performs non-destructive configuration and exposure checks.
It does not prove exploitability, identify every vulnerability, or replace a
manual security review or professional penetration test.
```

This is important both technically and academically.

---

# 60. Academic / Presentation Angle

The project should be explainable through these five concepts:

### Multi-Agent Systems

Different agents specialize in different security domains.

### Orchestration

The orchestrator controls execution and combines agent results.

### Risk Intelligence

Raw technical findings are transformed into contextual risk scores.

### Prioritization

Security teams receive ordered remediation actions rather than an unstructured list.

### Automation

The system produces a repeatable security assessment and report from a single command.

---

# 61. Architecture Diagram for Documentation

Use this exact conceptual diagram in the README:

```text
                    ┌─────────────────────────┐
                    │       Terminal CLI      │
                    │   User / Security Team  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Orchestrator       │
                    └────────────┬────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
          ▼                      ▼                      ▼
 ┌────────────────┐     ┌────────────────┐     ┌────────────────┐
 │ Recon Agent    │     │ Web Security   │     │ Configuration  │
 │                │     │ Agent          │     │ Agent          │
 └───────┬────────┘     └───────┬────────┘     └───────┬────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                ▼
                     ┌─────────────────────────┐
                     │   Finding Aggregator    │
                     └────────────┬────────────┘
                                  ▼
                     ┌─────────────────────────┐
                     │ Risk Intelligence Agent │
                     └────────────┬────────────┘
                                  ▼
                     ┌─────────────────────────┐
                     │ Priority + Remediation  │
                     └────────────┬────────────┘
                                  ▼
                     ┌─────────────────────────┐
                     │   Report Generation     │
                     │   Markdown / JSON       │
                     └─────────────────────────┘
```

---

# 62. Final Build Philosophy

The finished application should communicate:

> “This is an intelligent security assessment command center.”

It should NOT communicate:

> “This is a Python script that checks whether ports are open.”

The difference comes from:

```text
Specialized agents
        +
Central orchestration
        +
Structured findings
        +
Risk correlation
        +
Business context
        +
Prioritization
        +
Professional CLI UX
        +
Exportable reports
```

That is the actual product.

---

# 63. Final Instruction to the Development Agent

Build the system from the specification above.

Start with the smallest end-to-end path:

```text
CLI
→ Demo Target
→ Recon Agent
→ Web Security Agent
→ Configuration Agent
→ Aggregator
→ Risk Engine
→ Report Agent
→ Terminal Summary
```

Do not stop after scaffolding.

Do not create placeholder files without connecting them.

Do not claim a feature is complete until it has been exercised.

The first success criterion is:

```bash
cybersentinel demo
```

must execute from start to finish and produce:

1. visible multi-agent execution,
2. discovered assets,
3. structured findings,
4. deterministic risk score,
5. prioritized remediation list,
6. terminal report,
7. Markdown export,
8. JSON export.

After that works, implement authorized real-target inspection.

Keep the project compact, professional, modular, deterministic, and safe.
