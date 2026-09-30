# CyberSentinel: Developer Documentation

This document describes the architectural principles, codebase structure, and extension procedures for CyberSentinel developers.

---

## 1. Project Organization

```text
src/cybersentinel/
├── __init__.py           # Package version and constants
├── __main__.py           # python -m cybersentinel entrypoint
├── cli/
│   ├── app.py            # Typer CLI application definitions
│   ├── commands.py       # One-shot command runners
│   ├── rendering.py      # Rich terminal rendering engine
│   └── shell.py          # Persistent interactive shell
├── core/
│   ├── aggregator.py     # Deduplication and finding merging
│   ├── assessment.py     # Live pipeline assembly
│   ├── errors.py         # Domain exceptions
│   ├── event_bus.py      # Decoupled lifecycle event distribution
│   └── orchestrator.py   # Multi-agent execution coordinator
├── agents/
│   ├── base.py           # BaseAgent abstract interface
│   ├── recon.py          # Reconnaissance Agent
│   ├── web_security.py   # Web Security Agent
│   ├── configuration.py  # Configuration Agent
│   ├── risk_intelligence.py # Risk Intelligence Agent
│   └── report.py         # Report Agent
├── scanners/
│   ├── dns.py            # DNS scanner protocols & implementations
│   ├── http.py           # HTTP/HTTPS security scanner
│   ├── ports.py          # Safe restricted port scanner
│   └── tls.py            # TLS/SSL certificate & cipher scanner
├── risk/
│   ├── prioritization.py # P0-P3 mapping and queue sorting
│   ├── rules.py          # Explanation and recommendation rationale
│   ├── scoring.py        # Deterministic risk formulas
│   └── severity.py       # Severity enum and style mappings
├── models/
│   ├── asset.py          # Asset model
│   ├── assessment.py     # AssessmentContext and AgentResult
│   ├── events.py         # AssessmentEvent
│   ├── finding.py        # Finding model
│   └── target.py         # Target model
├── demo/
│   ├── data.py           # Synthetic fixture data loaders
│   └── scenario.py       # Demo pipeline builder
├── reporting/
│   ├── json_export.py    # Machine JSON serialization
│   └── markdown.py       # Markdown report generator
├── storage/
│   └── repository.py     # Assessment persistence in ~/.cybersentinel/history/
├── config/
│   └── settings.py       # Settings management
└── utils/
    ├── ids.py            # Unique ID generators
    ├── timestamps.py     # Datetime utilities
    └── validation.py     # Host and URL validation
```

---

## 2. Core Principles

1. **Decoupled Architecture**: Scanners collect raw observations; Agents process observations into structured `Finding` and `Asset` models; the Orchestrator manages state via `AssessmentContext`; Renderers display events without embedding security logic.
2. **Deterministic Risk Engine**: Every risk score is calculated via explicit, explainable mathematical formulas. No black-box estimations.
3. **Structured Agent Communication**: Agents never exchange free-form text. Every agent outputs an `AgentResult` containing typed models.
4. **Resilience & Safe Degradation**: Scanner timeouts and network warnings result in `status="partial"`; the assessment pipeline continues rather than terminating with unhandled exceptions.

---

## 3. Extending the Platform

### Adding a New Agent

1. Inherit from `BaseAgent` in `src/cybersentinel/agents/`:

```python
from cybersentinel.agents.base import BaseAgent
from cybersentinel.models.assessment import AgentResult, AssessmentContext

class CustomSecurityAgent(BaseAgent):
    name = "Custom Security Agent"
    description = "Inspects custom security properties"

    def run(self, context: AssessmentContext) -> AgentResult:
        self.emit_progress("Executing custom audit...")
        findings = []
        # Inspect context, run checks, create Finding instances
        return AgentResult(
            agent_name=self.name,
            status="success",
            findings=findings,
            observations=["Custom audit finished."],
        )
```

2. Register the agent inside `Orchestrator` or in `create_real_assessment_pipeline()`.

### Adding a Custom Scanner

1. Define a Protocol in `src/cybersentinel/scanners/`:

```python
from typing import Protocol

class CustomScanner(Protocol):
    def check_service(self, host: str) -> bool:
        ...
```

2. Implement a `RealCustomScanner` and a corresponding `DemoCustomScanner` returning deterministic data for offline simulation.

---

## 4. Risk Calculation Reference

Finding risk score is calculated as:

$$\text{Risk} = \Big( \text{Severity} \times 0.35 + \text{Exploitability} \times 0.20 + \text{Exposure} \times 0.20 + \text{AssetCriticality} \times 0.25 \Big) \times 10 \times \text{ConfidenceFactor}$$

Where:
- **Severity**: Base severity rating (1–10)
- **Exploitability**: Ease of remote exploitation (1–10)
- **Exposure**: Attack surface rating (1–10, e.g. public internet vs internal)
- **Asset Criticality**: Business impact rating of associated asset (1–10)
- **Confidence Factor**: Small calibration ($0.95 + 0.10 \times \frac{\text{Confidence}}{10}$)

The resulting score is clamped to $[0.0, 100.0]$:
- `0–24.9`: **LOW**
- `25–49.9`: **MODERATE**
- `50–74.9`: **HIGH**
- `75–100.0`: **CRITICAL**

---

## 5. Running Tests

```bash
# Run all tests
pytest -v

# Run specific suite
pytest tests/test_scoring.py
pytest tests/test_demo.py
```
