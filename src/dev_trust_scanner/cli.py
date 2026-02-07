"""Command-line interface for Dev Trust Scanner."""

import click


@click.command()
@click.argument('target', default='.')
@click.option('--help', '-h', is_flag=True, help='Show this message and exit.')
def main(target, help):
    """
    Dev Trust Scanner - Detect malicious patterns in developer tooling.

    Scans TARGET directory for suspicious patterns in npm scripts,
    VS Code tasks, and other developer configurations.
    """
    if help:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.exit()

    click.echo(f"🔍 Dev Trust Scanner v0.1.0")
    click.echo(f"Scanning: {target}")
    click.echo("⚠️  Scanner not yet implemented - this is a placeholder")


if __name__ == '__main__':
    main()
