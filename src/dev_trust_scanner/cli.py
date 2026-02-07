"""Command-line interface for Dev Trust Scanner."""

import logging
from pathlib import Path

import click

from .core.orchestrator import Orchestrator
from .core.reporting import JsonReporter, SarifReporter, TextReporter


@click.command()
@click.argument(
    "target",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default=".",
)
@click.option(
    "--plugin",
    "-p",
    multiple=True,
    help="Run specific plugin(s). Can be specified multiple times.",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--verbose", "-v", count=True, help="Increase verbosity (-v for INFO, -vv for DEBUG)"
)
@click.option(
    "--list-plugins", is_flag=True, help="List available plugins and exit"
)
def main(target, plugin, format, verbose, list_plugins):
    """
    Dev Trust Scanner - Detect malicious patterns in developer tooling.

    Scans TARGET directory for suspicious patterns in npm scripts,
    VS Code tasks, and other developer configurations.
    """
    # Setup logging
    if verbose == 1:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    elif verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")

    orchestrator = Orchestrator()

    # List plugins and exit
    if list_plugins:
        click.echo("Available plugins:")
        for plugin_meta in orchestrator.list_plugins():
            click.echo(f"  - {plugin_meta['name']}: {plugin_meta['description']}")
        return

    # Run scan
    plugin_filter = list(plugin) if plugin else None
    result = orchestrator.scan(target, plugin_filter=plugin_filter)

    # Generate report based on format
    if format == "text":
        reporter = TextReporter()
        reporter.report(result)
    elif format == "json":
        reporter = JsonReporter()
        output = reporter.report(result)
        click.echo(output)
    elif format == "sarif":
        reporter = SarifReporter()
        output = reporter.report(result)
        click.echo(output)

    # Exit code based on findings
    if result.summary["critical"] > 0 or result.summary["high"] > 0:
        raise SystemExit(1)
    elif result.summary["medium"] > 0 or result.summary["low"] > 0:
        raise SystemExit(1)
    else:
        raise SystemExit(0)


if __name__ == "__main__":
    main()
