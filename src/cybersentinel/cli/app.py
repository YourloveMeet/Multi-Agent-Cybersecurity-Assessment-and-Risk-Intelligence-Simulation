"""Typer CLI application entry point."""

from typing import Optional
import typer

from cybersentinel.cli.commands import (
    run_interactive_shell,
    execute_demo,
    execute_assess,
    execute_history,
    execute_config,
    execute_version,
)

app = typer.Typer(
    name="cybersentinel",
    help="Multi-Agent Cybersecurity Assessment & Risk Intelligence Platform",
    invoke_without_command=True,
    add_completion=False,
)


@app.callback()
def main_callback(ctx: typer.Context) -> None:
    """CyberSentinel: Terminal-first multi-agent cybersecurity intelligence platform."""
    if ctx.invoked_subcommand is None:
        run_interactive_shell()


@app.command(name="demo", help="Run deterministic multi-agent simulation assessment.")
def demo_command(
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File path to save assessment report."),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output."),
) -> None:
    execute_demo(json_output=json_output, output_path=output, no_color=no_color)


@app.command(name="assess", help="Execute authorized non-destructive security assessment against target.")
def assess_command(
    target: str = typer.Argument(..., help="Target domain or IP (e.g. example.com or https://example.com)"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile: 'standard' or 'quick'"),
    demo: bool = typer.Option(False, "--demo", help="Force deterministic simulation mode"),
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="File path to save assessment report"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored terminal output"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show verbose agent activity logs"),
) -> None:
    execute_assess(
        target=target,
        profile=profile,
        demo=demo,
        json_output=json_output,
        output_path=output,
        no_color=no_color,
        verbose=verbose,
    )


@app.command(name="history", help="Show previous assessment summaries.")
def history_command() -> None:
    execute_history()


@app.command(name="config", help="Display active CyberSentinel configuration.")
def config_command() -> None:
    execute_config()


@app.command(name="version", help="Show product version.")
def version_command() -> None:
    execute_version()


def main() -> int:
    """Console script entrypoint."""
    app()
    return 0


if __name__ == "__main__":
    main()
