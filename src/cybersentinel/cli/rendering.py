"""Rich terminal rendering engine for CyberSentinel CLI."""

from datetime import datetime
from typing import Any
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from cybersentinel import __version__
from cybersentinel.models.assessment import AssessmentContext
from cybersentinel.models.finding import Finding
from cybersentinel.risk.prioritization import PRIORITY_DESCRIPTIONS
from cybersentinel.risk.rules import RuleBasedIntelligenceProvider
from cybersentinel.risk.severity import SEVERITY_STYLES, Severity
from cybersentinel.utils.timestamps import format_time_hms


class CyberSentinelRenderer:
    """Provides styled terminal outputs using the Rich library."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self.intel_provider = RuleBasedIntelligenceProvider()

    def print_banner(self, subtitle: str = "Type 'help' for commands, 'demo' for simulation.") -> None:
        """Display CyberSentinel brand banner in Claude Code / Codex aesthetic."""
        content = Table.grid(expand=True, padding=(0, 1))
        content.add_column()

        title_text = Text()
        title_text.append("[+] CYBERSENTINEL ", style="bold cyan")
        title_text.append(f"v{__version__}", style="dim white")
        content.add_row(title_text)

        desc_text = Text("    Multi-Agent Defensive Cybersecurity Assessment & Risk Intelligence", style="dim italic")
        content.add_row(desc_text)
        content.add_row(Text(""))

        badges = Text()
        badges.append("    Engine: ", style="dim")
        badges.append("● Online ", style="bold green")
        badges.append(" │ ", style="dim")
        badges.append("Pipeline: ", style="dim")
        badges.append("5 Defensive Agents ", style="bold cyan")
        badges.append(" │ ", style="dim")
        badges.append("Scope: ", style="dim")
        badges.append("Safe Transport & Config", style="bold yellow")
        content.add_row(badges)
        content.add_row(Text(""))

        tips = Text()
        tips.append("    Quickstart: ", style="dim")
        tips.append("demo", style="bold white")
        tips.append(" (run simulated assessment)  •  ", style="dim")
        tips.append("assess <host>", style="bold white")
        tips.append("  •  ", style="dim")
        tips.append("help", style="bold white")
        content.add_row(tips)

        panel = Panel(
            content,
            box=box.ROUNDED,
            border_style="cyan",
            padding=(1, 2),
            expand=False,
        )
        self.console.print()
        self.console.print(panel)
        self.console.print()

    def print_target_meta(self, context: AssessmentContext) -> None:
        """Display assessment target and session profile details."""
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold cyan", justify="right")
        grid.add_column(style="white")

        grid.add_row("Target", context.target.display_name)
        grid.add_row("Mode", context.mode.capitalize())
        grid.add_row("Profile", context.profile.capitalize())
        grid.add_row("Started", format_time_hms(context.started_at))
        self.console.print(grid)
        self.console.print()

    def print_pipeline_status(self, agents_status: list[tuple[str, str]]) -> None:
        """Display agent pipeline checklist.
        
        agents_status: list of (agent_name, status) where status is:
          'completed', 'running', 'pending', 'failed'
        """
        table = Table(title="AGENT PIPELINE", show_header=False, box=None, padding=(0, 1))
        table.add_column("Icon", style="bold", width=3)
        table.add_column("Agent", style="bold")
        table.add_column("Status", style="dim")

        for name, status in agents_status:
            if status == "completed":
                table.add_row("[green]✓[/green]", name, "[green]completed[/green]")
            elif status == "running":
                table.add_row("[bold cyan]◉[/bold cyan]", f"[bold]{name}[/bold]", "[cyan]running...[/cyan]")
            elif status == "failed":
                table.add_row("[bold red]✗[/bold red]", name, "[red]failed[/red]")
            else:
                table.add_row("[dim]○[/dim]", name, "[dim]pending[/dim]")

        self.console.print(Panel(table, border_style="dim", expand=False))

    def print_event_log(self, timestamp: datetime, agent: str, message: str, is_warning: bool = False) -> None:
        """Print timestamped event log message."""
        time_str = format_time_hms(timestamp)
        agent_style = "bold yellow" if is_warning else "cyan"
        msg_style = "yellow" if is_warning else "white"
        self.console.print(f"[dim][{time_str}][/dim] [{agent_style}]{agent:<20}[/{agent_style}] [{msg_style}]{message}[/{msg_style}]")

    def print_risk_summary(self, context: AssessmentContext) -> None:
        """Display executive risk summary card."""
        category = context.overall_risk
        score = context.risk_score
        counts = context.severity_counts

        style_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MODERATE": "yellow",
            "LOW": "green",
        }
        color = style_map.get(category, "cyan")

        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_column(style="bold white", justify="left", width=18)
        summary_table.add_column(justify="left")

        summary_table.add_row("Overall Risk", f"[{color}]{category}[/{color}]")
        summary_table.add_row("Risk Score", f"[{color}]{score} / 100[/{color}]")
        summary_table.add_row("Critical Issues", f"[bold red]{counts.get('CRITICAL', 0)}[/bold red]")
        summary_table.add_row("High Issues", f"[red]{counts.get('HIGH', 0)}[/red]")
        summary_table.add_row("Medium Issues", f"[yellow]{counts.get('MEDIUM', 0)}[/yellow]")
        summary_table.add_row("Low Issues", f"[cyan]{counts.get('LOW', 0)}[/cyan]")
        summary_table.add_row("Discovered Assets", f"[white]{len(context.assets)}[/white]")
        summary_table.add_row("Scan Duration", f"[dim]{context.duration_seconds:.2f}s[/dim]")

        self.console.print(
            Panel(
                summary_table,
                title="[bold]RISK SUMMARY[/bold]",
                border_style=color,
                padding=(1, 2),
                expand=False,
            )
        )

    def print_findings_table(
        self,
        findings: list[Finding],
        severity_filter: str | None = None,
        priority_filter: str | None = None,
        agent_filter: str | None = None,
    ) -> None:
        """Display findings in a formatted table with optional filtering."""
        filtered = findings

        if severity_filter:
            target_sev = severity_filter.strip().upper()
            filtered = [f for f in filtered if f.severity.value == target_sev]

        if priority_filter:
            target_prio = priority_filter.strip().upper()
            filtered = [f for f in filtered if f.priority == target_prio]

        if agent_filter:
            target_agent = agent_filter.strip().lower()
            filtered = [f for f in filtered if target_agent in f.source_agent.lower()]

        if not filtered:
            self.console.print("[dim]No findings match the specified criteria.[/dim]")
            return

        table = Table(
            title=f"DISCOVERED FINDINGS ({len(filtered)})",
            header_style="bold cyan",
            border_style="dim",
            expand=True,
        )
        table.add_column("ID", style="bold white", width=10)
        table.add_column("Finding Title", style="white", min_width=32)
        table.add_column("Category", style="dim", width=22)
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Risk", justify="center", width=8)
        table.add_column("Priority", justify="center", width=10)

        prio_colors = {"P0": "bold red", "P1": "red", "P2": "yellow", "P3": "dim"}

        for f in filtered:
            sev_color = SEVERITY_STYLES.get(f.severity.value, "white")
            p_color = prio_colors.get(f.priority, "white")
            table.add_row(
                f.id,
                f.title,
                f.category,
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                f"{f.risk_score:.0f}",
                f"[{p_color}]{f.priority}[/{p_color}]",
            )

        self.console.print(table)

    def print_remediation_queue(self, findings: list[Finding]) -> None:
        """Display prioritized remediation queue ordered by urgency."""
        if not findings:
            self.console.print("[dim]No remediation actions pending.[/dim]")
            return

        table = Table(
            title="REMEDIATION QUEUE (PRIORITIZED)",
            header_style="bold cyan",
            border_style="dim",
            expand=True,
        )
        table.add_column("Priority", justify="center", width=10)
        table.add_column("Finding ID", style="bold white", width=10)
        table.add_column("Issue Title", style="white", min_width=32)
        table.add_column("Risk Score", justify="center", width=12)
        table.add_column("Recommended Action", style="italic dim", min_width=40)

        prio_colors = {"P0": "bold red", "P1": "red", "P2": "yellow", "P3": "dim"}

        for f in findings:
            p_color = prio_colors.get(f.priority, "white")
            table.add_row(
                f"[{p_color}]{f.priority}[/{p_color}]",
                f.id,
                f.title,
                f"{f.risk_score:.0f}",
                f.recommendation or "Review target configuration.",
            )

        self.console.print(table)

    def print_assets_table(self, context: AssessmentContext) -> None:
        """Display asset inventory table."""
        if not context.assets:
            self.console.print("[dim]No assets registered for this assessment.[/dim]")
            return

        table = Table(
            title=f"ASSET INVENTORY ({len(context.assets)})",
            header_style="bold cyan",
            border_style="dim",
            expand=True,
        )
        table.add_column("Asset ID", style="bold white", width=10)
        table.add_column("Asset Name", style="white", min_width=24)
        table.add_column("Type", style="dim", width=16)
        table.add_column("Endpoint", style="cyan", width=24)
        table.add_column("Criticality", justify="center", width=16)
        table.add_column("Exposure", justify="center", width=14)

        crit_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}

        for a in context.assets:
            endpoint = f"{a.host or context.target.host}:{a.port or 443}"
            c_color = crit_colors.get(a.criticality.lower(), "white")
            table.add_row(
                a.id,
                a.name,
                a.asset_type,
                endpoint,
                f"[{c_color}]{a.criticality.upper()} ({a.criticality_score}/10)[/{c_color}]",
                a.exposure,
            )

        self.console.print(table)

    def print_agents_table(self, context: AssessmentContext) -> None:
        """Display summary of executed agents."""
        if not context.agent_results:
            self.console.print("[dim]No agents have run in this session.[/dim]")
            return

        table = Table(
            title="AGENT EXECUTION STATUS",
            header_style="bold cyan",
            border_style="dim",
            expand=True,
        )
        table.add_column("Agent Name", style="bold white", min_width=24)
        table.add_column("Status", justify="center", width=14)
        table.add_column("Duration", justify="right", width=14)
        table.add_column("Findings", justify="center", width=12)

        for ar in context.agent_results:
            st_color = "green" if ar.status == "success" else ("yellow" if ar.status == "partial" else "red")
            table.add_row(
                ar.agent_name,
                f"[{st_color}]{ar.status.upper()}[/{st_color}]",
                f"{ar.duration_ms}ms",
                str(len(ar.findings)),
            )

        self.console.print(table)

    def print_finding_explanation(self, finding: Finding) -> None:
        """Display structured finding explanation with rationale."""
        rendered_text = self.intel_provider.explain_finding(finding)
        self.console.print(
            Panel(
                rendered_text,
                title=f"[bold]EXPLANATION: {finding.id}[/bold]",
                border_style="cyan",
                padding=(1, 2),
                expand=True,
            )
        )

    def print_history_table(self, history_records: list[dict[str, Any]]) -> None:
        """Display historical assessment table."""
        if not history_records:
            self.console.print("[dim]No historical assessments found.[/dim]")
            return

        table = Table(
            title=f"ASSESSMENT HISTORY ({len(history_records)})",
            header_style="bold cyan",
            border_style="dim",
            expand=True,
        )
        table.add_column("Assessment ID", style="bold white", width=24)
        table.add_column("Target Host", style="white", min_width=20)
        table.add_column("Risk Level", justify="center", width=14)
        table.add_column("Score", justify="center", width=10)
        table.add_column("Findings", justify="center", width=10)
        table.add_column("Date", style="dim", width=22)

        style_map = {"CRITICAL": "bold red", "HIGH": "red", "MODERATE": "yellow", "LOW": "green"}

        for r in history_records:
            risk = r.get("overall_risk", "UNKNOWN")
            color = style_map.get(risk, "white")
            date_str = r.get("started_at", "")[:19].replace("T", " ")
            table.add_row(
                r.get("id", ""),
                r.get("target", ""),
                f"[{color}]{risk}[/{color}]",
                f"{r.get('risk_score', 0):.0f}",
                str(r.get("findings_count", 0)),
                date_str,
            )

        self.console.print(table)

    def print_help(self) -> None:
        """Display command help tree."""
        tree = Tree("[bold cyan]CYBERSENTINEL COMMANDS[/bold cyan]")

        assess_node = tree.add("[bold]Assessment[/bold]")
        assess_node.add("[cyan]assess <target>[/cyan]     Run non-destructive authorized assessment")
        assess_node.add("[cyan]demo[/cyan]                Run deterministic multi-agent simulation")

        analysis_node = tree.add("[bold]Analysis[/bold]")
        analysis_node.add("[cyan]findings[/cyan]            Show discovered security findings")
        analysis_node.add("[cyan]findings --severity <S>[/cyan] Filter by CRITICAL, HIGH, MEDIUM, LOW")
        analysis_node.add("[cyan]assets[/cyan]              Show discovered asset inventory")
        analysis_node.add("[cyan]risk[/cyan]                Show risk summary and score metrics")
        analysis_node.add("[cyan]prioritize[/cyan]          Show prioritized remediation queue")
        analysis_node.add("[cyan]explain <id>[/cyan]        Explain finding impact, evidence, and rationale")
        analysis_node.add("[cyan]recommend <id>[/cyan]      Show concise remediation guidance")

        output_node = tree.add("[bold]Output & Export[/bold]")
        output_node.add("[cyan]report[/cyan]              Display formatted assessment report")
        output_node.add("[cyan]export markdown[/cyan]     Save Markdown report to reports directory")
        output_node.add("[cyan]export json[/cyan]         Save machine-readable JSON export")

        system_node = tree.add("[bold]System & Session[/bold]")
        system_node.add("[cyan]agents[/cyan]              Show agent execution pipeline status")
        system_node.add("[cyan]status[/cyan]              Show current assessment state")
        system_node.add("[cyan]history[/cyan]             List past assessments")
        system_node.add("[cyan]config[/cyan]              Display active configuration")
        system_node.add("[cyan]clear[/cyan]               Clear terminal screen")
        system_node.add("[cyan]version[/cyan]             Show CyberSentinel version")
        system_node.add("[cyan]exit / quit[/cyan]         Exit interactive session")

        self.console.print(Panel(tree, border_style="cyan", padding=(1, 2), expand=False))
