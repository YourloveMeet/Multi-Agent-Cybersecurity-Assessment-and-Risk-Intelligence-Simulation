from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.live import Live

from cybersentinel import __version__, __product_name__
from cybersentinel.cli.live_display import LiveAssessmentDisplay
from cybersentinel.cli.rendering import CyberSentinelRenderer
from cybersentinel.cli.shell import CyberSentinelShell
from cybersentinel.config.settings import Settings
from cybersentinel.core.assessment import create_real_assessment_pipeline
from cybersentinel.core.event_bus import EventBus
from cybersentinel.demo.scenario import run_demo_assessment
from cybersentinel.models.events import AssessmentEvent
from cybersentinel.reporting.json_export import JSONExportGenerator
from cybersentinel.reporting.markdown import MarkdownReportGenerator
from cybersentinel.storage.repository import AssessmentRepository


def run_interactive_shell() -> None:
    """Launch persistent interactive terminal application."""
    shell = CyberSentinelShell()
    shell.start()


def execute_demo(
    json_output: bool = False,
    output_path: Optional[str] = None,
    no_color: bool = False,
) -> None:
    """Execute deterministic demo simulation assessment."""
    console = Console(no_color=no_color)
    repository = AssessmentRepository()

    if json_output:
        context = run_demo_assessment(pacing=False)
        repository.save_assessment(context)
        payload = JSONExportGenerator().generate(context)
        print(payload)
        if output_path:
            out_p = Path(output_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                f.write(payload)
        return

    display = LiveAssessmentDisplay(console)
    display.init_target(target_name="acme-demo.local", mode="simulation", profile="standard")

    bus = EventBus()
    bus.subscribe(display.on_event)

    with Live(display.build_renderable(), console=console, refresh_per_second=10, transient=False) as live:
        def on_refresh(_):
            live.update(display.build_renderable())

        bus.subscribe(on_refresh)
        context = run_demo_assessment(event_bus=bus, pacing=True)
        live.update(display.build_renderable())

    repository.save_assessment(context)
    display.render_final_dashboard(context)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        if output_path.endswith(".json"):
            payload = JSONExportGenerator().generate(context)
        else:
            payload = MarkdownReportGenerator().generate(context)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(payload)
        console.print(f"[green]✓ Output saved to:[/green] [bold]{out_p}[/bold]")


def execute_assess(
    target: str,
    profile: str = "standard",
    demo: bool = False,
    json_output: bool = False,
    output_path: Optional[str] = None,
    no_color: bool = False,
    verbose: bool = False,
) -> None:
    """Execute live or demo assessment against target with live TUI."""
    console = Console(no_color=no_color)
    repository = AssessmentRepository()

    if demo:
        execute_demo(json_output=json_output, output_path=output_path, no_color=no_color)
        return

    if not json_output:
        renderer = CyberSentinelRenderer(console)
        renderer.print_banner()
        console.print(f"[bold]Target:[/bold] {target}")
        console.print("[yellow]This assessment performs safe, non-destructive configuration and transport checks.[/yellow]")
        console.print("[yellow]Only continue if you are explicitly authorized to assess this target.[/yellow]\n")

        confirm = typer.confirm("Confirm authorization to assess this target?", default=False)
        if not confirm:
            console.print("[dim]Assessment aborted: authorization not confirmed.[/dim]")
            raise typer.Exit(code=1)

    bus = EventBus()

    if json_output:
        try:
            context, orchestrator, agents = create_real_assessment_pipeline(
                target_input=target,
                profile=profile,
                authorized=True,
                event_bus=bus,
                pacing=False,
            )
            context = orchestrator.run_assessment(context, pipeline_agents=agents)
            repository.save_assessment(context)
            payload = JSONExportGenerator().generate(context)
            print(payload)
        except Exception as e:
            console.print(f"[bold red]Assessment error:[/bold red] {str(e)}")
            raise typer.Exit(code=1)
    else:
        display = LiveAssessmentDisplay(console)
        display.init_target(target_name=target, mode="authorized", profile=profile)
        bus.subscribe(display.on_event)

        try:
            with Live(display.build_renderable(), console=console, refresh_per_second=10, transient=False) as live:
                def on_refresh(_):
                    live.update(display.build_renderable())

                bus.subscribe(on_refresh)
                context, orchestrator, agents = create_real_assessment_pipeline(
                    target_input=target,
                    profile=profile,
                    authorized=True,
                    event_bus=bus,
                    pacing=True,
                )
                context = orchestrator.run_assessment(context, pipeline_agents=agents)
                live.update(display.build_renderable())

            repository.save_assessment(context)
            display.render_final_dashboard(context)
        except Exception as e:
            console.print(f"[bold red]Assessment error:[/bold red] {str(e)}")
            raise typer.Exit(code=1)

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        if json_output or output_path.endswith(".json"):
            payload = JSONExportGenerator().generate(context)
        else:
            payload = MarkdownReportGenerator().generate(context)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(payload)
        console.print(f"[green]✓ Output saved to:[/green] [bold]{out_p}[/bold]")


def execute_history() -> None:
    """Display history of past assessments."""
    console = Console()
    renderer = CyberSentinelRenderer(console)
    repo = AssessmentRepository()
    records = repo.list_history()
    renderer.print_history_table(records)


def execute_config() -> None:
    """Print active configuration."""
    console = Console()
    settings = Settings.load()
    console.print(f"[bold cyan]{__product_name__} Configuration (~/.cybersentinel/config.toml):[/bold cyan]\n")
    console.print(settings.to_toml(), markup=False)


def execute_version() -> None:
    """Print product version information."""
    console = Console()
    console.print(f"[bold cyan]{__product_name__}[/bold cyan] v[bold white]{__version__}[/bold white]")
