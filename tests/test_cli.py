"""Unit tests for CLI commands and shell dispatch."""

from typer.testing import CliRunner
from cybersentinel.cli.app import app
from cybersentinel.cli.shell import CyberSentinelShell

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "CyberSentinel" in result.stdout
    assert "v0.1.0" in result.stdout


def test_cli_config():
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    assert "[scanner]" in result.stdout
    assert "[assessment]" in result.stdout


def test_cli_demo_json():
    result = runner.invoke(app, ["demo", "--json"])
    assert result.exit_code == 0
    assert '"target": "acme-demo.local"' in result.stdout
    assert '"overall_risk":' in result.stdout
    assert '"findings":' in result.stdout


def test_cli_demo_terminal():
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "acme-demo.local" in result.stdout
    assert "RISK SUMMARY" in result.stdout
    assert "REMEDIATION QUEUE" in result.stdout


def test_shell_command_dispatch():
    shell = CyberSentinelShell()

    # 1. Test help
    assert shell.dispatch_command("help") is True

    # 2. Test demo execution in shell
    assert shell.dispatch_command("demo") is True
    assert shell.current_context is not None
    assert shell.current_context.target.host == "acme-demo.local"

    # 3. Test status
    assert shell.dispatch_command("status") is True

    # 4. Test agents
    assert shell.dispatch_command("agents") is True

    # 5. Test findings
    assert shell.dispatch_command("findings") is True
    assert shell.dispatch_command("findings --severity HIGH") is True

    # 6. Test assets
    assert shell.dispatch_command("assets") is True

    # 7. Test risk
    assert shell.dispatch_command("risk") is True

    # 8. Test prioritize
    assert shell.dispatch_command("prioritize") is True

    # 9. Test explain
    first_id = shell.current_context.findings[0].id
    assert shell.dispatch_command(f"explain {first_id}") is True

    # 10. Test recommend
    assert shell.dispatch_command(f"recommend {first_id}") is True

    # 11. Test report
    assert shell.dispatch_command("report") is True

    # 12. Test export
    assert shell.dispatch_command("export markdown") is True
    assert shell.dispatch_command("export json") is True

    # 13. Test history
    assert shell.dispatch_command("history") is True

    # 14. Test exit
    assert shell.dispatch_command("exit") is False
