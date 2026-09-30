"""Interactive terminal shell session for CyberSentinel."""

import os
import shlex
import sys
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown

from cybersentinel import __version__, __product_name__
from cybersentinel.cli.live_display import LiveAssessmentDisplay
from cybersentinel.cli.rendering import CyberSentinelRenderer
from cybersentinel.config.settings import Settings
from cybersentinel.core.assessment import create_real_assessment_pipeline
from cybersentinel.core.event_bus import EventBus
from cybersentinel.demo.scenario import run_demo_assessment
from cybersentinel.models.assessment import AssessmentContext
from cybersentinel.models.events import AssessmentEvent
from cybersentinel.reporting.markdown import MarkdownReportGenerator
from cybersentinel.storage.repository import AssessmentRepository


class CyberSentinelShell:
    """Persistent interactive shell managing active assessment state and commands."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()
        self.renderer = CyberSentinelRenderer(self.console)
        self.repository = AssessmentRepository()
        self.settings = Settings.load()
        self.current_context: AssessmentContext | None = None

    def start(self) -> None:
        """Launch the persistent terminal session loop."""
        self.renderer.print_banner(subtitle="Type 'help' for commands, 'demo' for simulation, 'exit' to quit.")

        while True:
            try:
                if self.current_context:
                    target_short = self.current_context.target.display_name
                    cat = self.current_context.overall_risk or "ACTIVE"
                    color = "red" if cat in ("CRITICAL", "HIGH") else "yellow" if cat == "MODERATE" else "green"
                    prompt_markup = f"[bold green]●[/bold green] [bold cyan]cybersentinel[/bold cyan] [dim][[/dim][{color}]{target_short}[/{color}][dim]][/dim] [bold white]›[/bold white] "
                else:
                    prompt_markup = "[bold green]●[/bold green] [bold cyan]cybersentinel[/bold cyan] [bold white]›[/bold white] "

                user_input = self.console.input(prompt_markup).strip()
                if not user_input:
                    continue

                if not self.dispatch_command(user_input):
                    break
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[dim]Session terminated by user. Goodbye.[/dim]")
                break
            except Exception as e:
                self.console.print(f"[bold red]Error:[/bold red] {str(e)}")

    def dispatch_command(self, cmd_line: str) -> bool:
        """Parse and execute shell command. Return False to terminate loop."""
        parts = shlex.split(cmd_line)
        if not parts:
            return True

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("exit", "quit", "q"):
            self.console.print("[dim]Exiting CyberSentinel. Stay safe.[/dim]")
            return False

        elif cmd == "help":
            self.renderer.print_help()

        elif cmd == "version":
            self.console.print(f"[bold cyan]{__product_name__}[/bold cyan] version [bold white]{__version__}[/bold white]")

        elif cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")
            self.renderer.print_banner()

        elif cmd == "config":
            self._handle_config()

        elif cmd == "demo":
            self._handle_demo()

        elif cmd == "assess":
            self._handle_assess(args)

        elif cmd == "status":
            self._handle_status()

        elif cmd == "agents":
            self._handle_agents()

        elif cmd == "findings":
            self._handle_findings(args)

        elif cmd == "assets":
            self._handle_assets()

        elif cmd == "risk":
            self._handle_risk()

        elif cmd == "prioritize":
            self._handle_prioritize()

        elif cmd == "explain":
            self._handle_explain(args)

        elif cmd == "recommend":
            self._handle_recommend(args)

        elif cmd == "report":
            self._handle_report()

        elif cmd == "export":
            self._handle_export(args)

        elif cmd == "history":
            self._handle_history()

        else:
            self.console.print(f"[red]Unknown command: '{cmd}'. Type 'help' for available commands.[/red]")

        return True

    def _handle_demo(self) -> None:
        """Run complete deterministic simulation assessment with Claude Code / Codex live TUI."""
        display = LiveAssessmentDisplay(self.console)
        display.init_target(target_name="acme-demo.local", mode="simulation", profile="standard")

        bus = EventBus()
        bus.subscribe(display.on_event)

        with Live(display.build_renderable(), console=self.console, refresh_per_second=10, transient=False) as live:
            def on_refresh(_):
                live.update(display.build_renderable())

            bus.subscribe(on_refresh)
            self.current_context = run_demo_assessment(event_bus=bus, pacing=True)
            live.update(display.build_renderable())

        # Persist assessment in history
        self.repository.save_assessment(self.current_context)

        # Render stunning Executive Dashboard
        display.render_final_dashboard(self.current_context)

    def _handle_assess(self, args: list[str]) -> None:
        """Run authorized live assessment against a target host with live TUI."""
        if not args:
            self.console.print("[red]Usage: assess <target> [--profile standard|quick][/red]")
            return

        target_input = args[0]
        profile = "standard"
        if len(args) > 2 and args[1] == "--profile":
            profile = args[2]

        self.console.print(f"\n[bold]Target:[/bold] {target_input}")
        self.console.print("[yellow]This assessment mode performs safe non-destructive security checks.[/yellow]")
        self.console.print("[yellow]Only continue if you are explicitly authorized to assess this target.[/yellow]\n")

        confirm = self.console.input("[bold yellow]Proceed with assessment? [y/N]: [/bold yellow]").strip().lower()
        if confirm not in ("y", "yes"):
            self.console.print("[dim]Assessment cancelled.[/dim]\n")
            return

        display = LiveAssessmentDisplay(self.console)
        display.init_target(target_name=target_input, mode="authorized", profile=profile)

        bus = EventBus()
        bus.subscribe(display.on_event)

        try:
            with Live(display.build_renderable(), console=self.console, refresh_per_second=10, transient=False) as live:
                def on_refresh(_):
                    live.update(display.build_renderable())

                bus.subscribe(on_refresh)
                context, orchestrator, agents = create_real_assessment_pipeline(
                    target_input=target_input,
                    profile=profile,
                    authorized=True,
                    event_bus=bus,
                    pacing=True,
                )
                self.current_context = orchestrator.run_assessment(context, pipeline_agents=agents)
                live.update(display.build_renderable())

            self.repository.save_assessment(self.current_context)
            display.render_final_dashboard(self.current_context)
        except Exception as e:
            self.console.print(f"[bold red]Assessment failed:[/bold red] {str(e)}\n")

    def _handle_status(self) -> None:
        """Display state of active assessment."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return

        ctx = self.current_context
        self.console.print(f"[bold cyan]Active Assessment:[/bold cyan] {ctx.assessment_id}")
        self.console.print(f"Target:           {ctx.target.display_name}")
        self.console.print(f"Mode:             {ctx.mode.capitalize()}")
        self.console.print(f"Profile:          {ctx.profile.capitalize()}")
        self.console.print(f"Started:          {ctx.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        self.console.print(f"Status:           {'Completed' if ctx.completed_at else 'In Progress'}")
        self.console.print(f"Agents executed:  {len(ctx.agent_results)}")
        self.console.print(f"Total findings:   {len(ctx.findings)}")
        self.console.print(f"Overall Risk:     {ctx.overall_risk} ({ctx.risk_score}/100)")
        self.console.print()

    def _handle_agents(self) -> None:
        """Display status of agents."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return
        self.renderer.print_agents_table(self.current_context)

    def _handle_findings(self, args: list[str]) -> None:
        """Display findings table with optional filters."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return

        sev_filter = None
        prio_filter = None
        agent_filter = None

        i = 0
        while i < len(args):
            if args[i] == "--severity" and i + 1 < len(args):
                sev_filter = args[i + 1]
                i += 2
            elif args[i] == "--priority" and i + 1 < len(args):
                prio_filter = args[i + 1]
                i += 2
            elif args[i] == "--agent" and i + 1 < len(args):
                agent_filter = args[i + 1]
                i += 2
            else:
                i += 1

        self.renderer.print_findings_table(
            self.current_context.findings,
            severity_filter=sev_filter,
            priority_filter=prio_filter,
            agent_filter=agent_filter,
        )

    def _handle_assets(self) -> None:
        """Display discovered asset inventory."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return
        self.renderer.print_assets_table(self.current_context)

    def _handle_risk(self) -> None:
        """Display risk summary."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return
        self.renderer.print_risk_summary(self.current_context)

    def _handle_prioritize(self) -> None:
        """Display prioritized remediation queue."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return
        self.renderer.print_remediation_queue(self.current_context.findings)

    def _handle_explain(self, args: list[str]) -> None:
        """Display detailed explanation for a finding ID."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return
        if not args:
            self.console.print("[red]Usage: explain <finding_id> (e.g. explain FIND-001)[/red]")
            return

        finding_id = args[0]
        finding = self.current_context.get_finding(finding_id)
        if not finding:
            self.console.print(f"[red]Finding ID '{finding_id}' not found in active assessment.[/red]")
            return

        self.renderer.print_finding_explanation(finding)

    def _handle_recommend(self, args: list[str]) -> None:
        """Display actionable recommendation for a finding ID."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return
        if not args:
            self.console.print("[red]Usage: recommend <finding_id> (e.g. recommend FIND-001)[/red]")
            return

        finding_id = args[0]
        finding = self.current_context.get_finding(finding_id)
        if not finding:
            self.console.print(f"[red]Finding ID '{finding_id}' not found in active assessment.[/red]")
            return

        text = self.renderer.intel_provider.recommend_finding(finding)
        self.console.print(f"\n[bold cyan]Remediation Guidance for {finding.id}:[/bold cyan]")
        self.console.print(f"[white]{text}[/white]\n")

    def _handle_report(self) -> None:
        """Display rendered Markdown report to the terminal."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return

        md_content = MarkdownReportGenerator().generate(self.current_context)
        self.console.print(Markdown(md_content))

    def _handle_export(self, args: list[str]) -> None:
        """Export report to markdown or JSON."""
        if not self.current_context:
            self.console.print("[dim]No active assessment in session. Run 'demo' or 'assess <target>' first.[/dim]")
            return

        format_type = args[0].lower() if args else "all"

        md_path, json_path = self.repository.export_reports(self.current_context, target_dir=self.settings.output.reports_dir)

        if format_type in ("md", "markdown"):
            self.console.print(f"[green]✓ Markdown report written to:[/green] [bold]{md_path}[/bold]")
        elif format_type == "json":
            self.console.print(f"[green]✓ JSON export written to:[/green] [bold]{json_path}[/bold]")
        else:
            self.console.print(f"[green]✓ Markdown report written to:[/green] [bold]{md_path}[/bold]")
            self.console.print(f"[green]✓ JSON export written to:[/green] [bold]{json_path}[/bold]")

    def _handle_history(self) -> None:
        """List past assessments."""
        records = self.repository.list_history()
        self.renderer.print_history_table(records)

    def _handle_config(self) -> None:
        """Display active configuration."""
        self.console.print("[bold cyan]Active CyberSentinel Configuration:[/bold cyan]")
        self.console.print(self.settings.to_toml(), markup=False)
