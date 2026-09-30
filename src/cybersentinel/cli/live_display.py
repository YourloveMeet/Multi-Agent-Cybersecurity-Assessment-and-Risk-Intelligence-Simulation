"""Claude Code / Codex CLI inspired live interactive display for CyberSentinel assessments."""

from datetime import datetime
import time
from typing import Any
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from cybersentinel.models.assessment import AssessmentContext
from cybersentinel.models.events import AssessmentEvent
from cybersentinel.risk.prioritization import PRIORITY_DESCRIPTIONS
from cybersentinel.risk.severity import SEVERITY_STYLES


class AgentState:
    """Tracks state and progress of an agent during execution."""

    def __init__(self, name: str, icon: str = "agent"):
        self.name = name
        self.status = "pending"  # "pending", "running", "completed", "failed"
        self.current_task = "Queued in pipeline"
        self.sub_tasks: list[str] = []
        self.start_time: float | None = None
        self.duration_seconds: float = 0.0
        self.findings_count: int = 0
        self.summary_badge: str = ""


class LiveAssessmentDisplay:
    """Manages the full-screen dynamic TUI during multi-agent assessments."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self.start_wall_time = datetime.now()
        self.start_perf_time = time.perf_counter()

        self.target_name = "acme-demo.local"
        self.mode = "Simulation"
        self.profile = "Standard"

        # Ordered pipeline agents
        self.agents: dict[str, AgentState] = {
            "Reconnaissance Agent": AgentState("Reconnaissance Agent"),
            "Web Security Agent": AgentState("Web Security Agent"),
            "Configuration Agent": AgentState("Configuration Agent"),
            "Risk Intelligence Agent": AgentState("Risk Intelligence Agent"),
            "Report Agent": AgentState("Report Agent"),
        }

        self.telemetry_feed: list[tuple[str, str, str]] = []  # (timestamp, badge, message)
        self.is_completed = False
        self.overall_risk = "CALCULATING"
        self.risk_score = 0.0

    def init_target(self, target_name: str, mode: str, profile: str) -> None:
        """Set target metadata for HUD."""
        self.target_name = target_name
        self.mode = mode.capitalize()
        self.profile = profile.capitalize()
        self.start_perf_time = time.perf_counter()
        self.start_wall_time = datetime.now()

    def on_event(self, ev: AssessmentEvent) -> None:
        """Handle incoming assessment events and update display state."""
        time_str = ev.timestamp.strftime("%H:%M:%S")

        if ev.type == "agent.started" and ev.agent in self.agents:
            st = self.agents[ev.agent]
            st.status = "running"
            st.start_time = time.perf_counter()
            st.current_task = "Executing security inspection..."

        elif ev.type == "agent.progress" and ev.agent in self.agents:
            st = self.agents[ev.agent]
            st.current_task = ev.message
            st.sub_tasks.append(ev.message)
            if len(st.sub_tasks) > 4:
                st.sub_tasks.pop(0)

            # Record in telemetry feed if significant
            if any(k in ev.message.lower() for k in ["resolved", "reachable", "asset", "discovered", "port"]):
                self.telemetry_feed.append((time_str, "[bold cyan]● PROGRESS[/bold cyan]", ev.message))

        elif ev.type == "finding.discovered":
            finding_title = ev.message.replace("Finding discovered: ", "")
            severity = ev.metadata.get("severity", "MEDIUM")
            sev_color = SEVERITY_STYLES.get(severity, "yellow")

            # Update count for the agent
            if ev.agent in self.agents:
                self.agents[ev.agent].findings_count += 1

            self.telemetry_feed.append(
                (time_str, f"[{sev_color}]★ {severity}[/{sev_color}]", finding_title)
            )

        elif ev.type == "agent.completed" and ev.agent in self.agents:
            st = self.agents[ev.agent]
            st.status = "completed"
            if st.start_time:
                st.duration_seconds = time.perf_counter() - st.start_time

            # Set human summary badge
            if ev.agent == "Reconnaissance Agent":
                st.summary_badge = "[green]Host resolved • Assets mapped[/green]"
            elif ev.agent == "Web Security Agent":
                st.summary_badge = f"[yellow]{st.findings_count} findings identified[/yellow]"
            elif ev.agent == "Configuration Agent":
                st.summary_badge = f"[yellow]{st.findings_count} findings identified[/yellow]"
            elif ev.agent == "Risk Intelligence Agent":
                st.summary_badge = "[bold green]Scored & Prioritized[/bold green]"
            elif ev.agent == "Report Agent":
                st.summary_badge = "[bold green]Reports generated[/bold green]"

        elif ev.type == "risk.calculated":
            self.overall_risk = ev.metadata.get("overall_risk", "UNKNOWN")
            self.risk_score = ev.metadata.get("risk_score", 0.0)

        elif ev.type == "assessment.completed":
            self.is_completed = True

        if len(self.telemetry_feed) > 8:
            self.telemetry_feed = self.telemetry_feed[-8:]

    def build_renderable(self) -> Group:
        """Compose the live GUI renderable group for the current frame."""
        elapsed = time.perf_counter() - self.start_perf_time
        elapsed_str = f"{elapsed:.1f}s"

        # 1. Target HUD Header
        hud_table = Table.grid(expand=True)
        hud_table.add_column(justify="left", ratio=3)
        hud_table.add_column(justify="right", ratio=2)

        hud_left = Text.from_markup(
            f"[bold white on cyan] CYBERSENTINEL [/bold white on cyan]  Target: [bold white]{self.target_name}[/bold white]   Profile: [cyan]{self.profile}[/cyan]   Mode: [green]{self.mode}[/green]"
        )

        hud_right = Text.from_markup(
            f"[bold black on green] ✔ Finished in {elapsed_str} [/bold black on green]"
            if self.is_completed
            else f"[bold white on blue] ⠋ Running ({elapsed_str}) [/bold white on blue]"
        )

        hud_table.add_row(hud_left, hud_right)
        hud_panel = Panel(hud_table, box=box.ROUNDED, border_style="cyan", padding=(0, 1))

        # 2. Agent Pipeline Status Panel
        pipeline_table = Table(
            expand=True,
            box=None,
            padding=(0, 1),
            show_header=True,
            header_style="bold dim white",
        )
        pipeline_table.add_column("Status", width=12, justify="center")
        pipeline_table.add_column("Security Agent", width=26, style="bold white")
        pipeline_table.add_column("Current Task / Summary", ratio=1)
        pipeline_table.add_column("Time", width=8, justify="right", style="dim")

        for name, st in self.agents.items():
            if st.status == "completed":
                status_icon = "[bold green]✔ COMPLETE[/bold green]"
                time_disp = f"{st.duration_seconds:.1f}s"
                detail = st.summary_badge or "[green]Done[/green]"
                pipeline_table.add_row(status_icon, name, detail, time_disp)

            elif st.status == "running":
                # Active agent with animated spinner and sub-tasks
                status_icon = "[bold cyan]⠋ ACTIVE  [/bold cyan]"
                cur_elapsed = (time.perf_counter() - st.start_time) if st.start_time else 0.0
                time_disp = f"{cur_elapsed:.1f}s"

                # Sub-task details
                detail_text = Text()
                detail_text.append(f"{st.current_task}\n", style="bold cyan")
                if st.sub_tasks:
                    for i, sub in enumerate(st.sub_tasks[-3:]):
                        prefix = "  └─ " if i == len(st.sub_tasks[-3:]) - 1 else "  ├─ "
                        detail_text.append(f"{prefix}{sub}\n", style="dim cyan")

                pipeline_table.add_row(status_icon, f"[bold cyan]{name}[/bold cyan]", detail_text, time_disp)

            elif st.status == "failed":
                status_icon = "[bold red]✗ FAILED  [/bold red]"
                pipeline_table.add_row(status_icon, name, "[red]Agent fault[/red]", "-")
            else:
                status_icon = "[dim]○ QUEUED  [/dim]"
                pipeline_table.add_row(status_icon, f"[dim]{name}[/dim]", "[dim]Waiting for upstream agents...[/dim]", "-")

        pipeline_panel = Panel(
            pipeline_table,
            title="[bold cyan]MULTI-AGENT ASSESSMENT PIPELINE[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan" if not self.is_completed else "green",
            padding=(0, 1),
        )

        # 3. Live Telemetry & Discovery Feed
        feed_table = Table.grid(expand=True, padding=(0, 1))
        feed_table.add_column(width=10, style="dim")
        feed_table.add_column(width=16)
        feed_table.add_column(style="white", ratio=1)

        if not self.telemetry_feed:
            feed_table.add_row("", "[dim]● IDLE[/dim]", "[dim]Telemetry stream initializing...[/dim]")
        else:
            for t_str, badge, msg in self.telemetry_feed[-4:]:
                feed_table.add_row(f"[{t_str}]", badge, msg)

        telemetry_panel = Panel(
            feed_table,
            title="[bold]LIVE DETECTION STREAM[/bold]",
            box=box.ROUNDED,
            border_style="dim",
            padding=(0, 1),
        )

        return Group(hud_panel, pipeline_panel, telemetry_panel)

    def render_final_dashboard(self, context: AssessmentContext) -> None:
        """Render the complete executive summary dashboard after assessment finishes."""
        counts = context.severity_counts
        score = context.risk_score
        cat = context.overall_risk

        # Gauge representation: 20 blocks
        filled = int((score / 100.0) * 20)
        unfilled = 20 - filled
        gauge_bar = "█" * filled + "░" * unfilled

        color_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MODERATE": "yellow",
            "LOW": "green",
        }
        color = color_map.get(cat, "cyan")

        # Hero Banner
        hero = Table.grid(expand=True, padding=(0, 2))
        hero.add_column(ratio=3)
        hero.add_column(ratio=2)

        left_text = Text()
        left_text.append("THREAT POSTURE: ", style="bold dim white")
        left_text.append(f"{cat}\n", style=f"{color} bold")
        left_text.append("RISK SCORE    : ", style="bold dim white")
        left_text.append(f"{score:.1f} / 100  ", style=f"{color} bold")
        left_text.append("[", style=color)
        left_text.append(gauge_bar, style=color)
        left_text.append("]\n\n", style=color)
        left_text.append("SEVERITY TOTALS: ", style="bold dim white")
        left_text.append_text(
            Text.from_markup(
                f"[bold red]{counts.get('CRITICAL', 0)} Critical[/bold red]  •  "
                f"[red]{counts.get('HIGH', 0)} High[/red]  •  "
                f"[yellow]{counts.get('MEDIUM', 0)} Medium[/yellow]  •  "
                f"[cyan]{counts.get('LOW', 0)} Low[/cyan]"
            )
        )

        right_text = Text()
        right_text.append("Target Asset Boundary:\n", style="bold cyan")
        right_text.append_text(
            Text.from_markup(
                f"  • Target: [bold white]{context.target.display_name}[/bold white]\n"
                f"  • Assets Identified: [bold white]{len(context.assets)} Services[/bold white]\n"
                f"  • Total Findings: [bold white]{len(context.findings)} Issues[/bold white]\n"
                f"  • Assessment Time: [bold white]{context.duration_seconds:.2f}s[/bold white]\n"
            )
        )

        hero.add_row(left_text, right_text)

        self.console.print()
        self.console.print(
            Panel(
                hero,
                title="[bold]RISK SUMMARY & THREAT INTELLIGENCE[/bold]",
                box=box.ROUNDED,
                border_style=color,
                padding=(1, 2),
            )
        )

        # Top Prioritized Action Queue
        self.console.print("\n[bold cyan]REMEDIATION QUEUE (PRIORITY ORDER)[/bold cyan]")
        prio_table = Table(
            expand=True,
            box=box.ROUNDED,
            border_style="dim",
            header_style="bold cyan",
        )
        prio_table.add_column("Priority", justify="center", width=12, no_wrap=True)
        prio_table.add_column("ID", style="bold white", width=10, no_wrap=True)
        prio_table.add_column("Security Finding", style="white", ratio=3)
        prio_table.add_column("Risk", justify="center", width=6, no_wrap=True)
        prio_table.add_column("Actionable Remediation", style="dim italic", ratio=4)

        prio_badges = {
            "P0": "[bold white on red] P0 CRIT [/bold white on red]",
            "P1": "[bold white on dark_red] P1 HIGH [/bold white on dark_red]",
            "P2": "[bold black on yellow] P2 PLAN [/bold black on yellow]",
            "P3": "[dim] P3 HARD [/dim]",
        }

        for f in context.findings[:6]:
            badge = prio_badges.get(f.priority, f.priority)
            first_line = f.recommendation.splitlines()[0].strip() if f.recommendation else ""
            action = (first_line[:65] + "...") if len(first_line) > 65 else first_line
            prio_table.add_row(
                badge,
                f.id,
                f.title,
                f"{f.risk_score:.0f}",
                action,
            )

        self.console.print(prio_table)

        # Prompt hint bar
        hint_text = Text()
        hint_text.append(" Explore results: ", style="bold cyan")
        hint_text.append("findings ", style="bold white")
        hint_text.append("• ", style="dim")
        hint_text.append("explain FIND-011 ", style="bold white")
        hint_text.append("• ", style="dim")
        hint_text.append("assets ", style="bold white")
        hint_text.append("• ", style="dim")
        hint_text.append("report ", style="bold white")
        hint_text.append("• ", style="dim")
        hint_text.append("export markdown", style="bold white")
        self.console.print(Panel(hint_text, box=box.ROUNDED, border_style="dim", padding=(0, 1)))
        self.console.print()
