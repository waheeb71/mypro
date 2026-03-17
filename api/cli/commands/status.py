import click
import sys
from api.cli.core.client import get_client

@click.group()
def status():
    """System status and health"""
    pass

@status.command()
def show():
    """Show system status"""
    try:
        client = get_client()
        data = client.get('status')
        click.echo(click.style('\n=== System Status ===\n', fg='cyan', bold=True))
        click.echo(f"Status: {click.style(data['status'].upper(), fg='green' if data['status'] == 'operational' else 'red')}")
        click.echo(f"Uptime: {data['uptime_seconds']:.0f} seconds")
        click.echo(f"CPU Usage: {data['cpu_usage']:.1f}%")
        click.echo(f"Memory Usage: {data['memory_usage']:.1f}%")
        click.echo(f"Active Connections: {data['active_connections']}")
        click.echo(f"Rules Count: {data['rules_count']}")
        click.echo(f"ML Models: {'Loaded' if data['ml_models_loaded'] else 'Not loaded'}")
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)

@status.command()
def health():
    """Check API health"""
    try:
        client = get_client()
        response = client.session.get(f"{client.api_url.replace('/api/v1', '')}/api/v1/health")
        if response.status_code == 200:
            click.echo(click.style('✓ API is healthy', fg='green'))
        else:
            click.echo(click.style('✗ API is unhealthy', fg='red'), err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)
