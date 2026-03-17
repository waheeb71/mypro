import click
import sys
from api.cli.core.client import get_client

@click.group()
def profile():
    """IP profiling"""
    pass

@profile.command()
@click.argument('ip_address')
def show(ip_address: str):
    """Show IP profile"""
    try:
        client = get_client()
        data = client.get(f'profiles/{ip_address}')
        
        click.echo(click.style(f'\n=== Profile: {ip_address} ===\n', fg='cyan', bold=True))
        click.echo(f"Reputation Score: {data.get('reputation_score', 0):.1f}")
        click.echo(f"Total Connections: {data.get('total_connections', 0):,}")
        click.echo(f"First Seen: {data.get('first_seen', 'N/A')}")
        click.echo(f"Last Seen: {data.get('last_seen', 'N/A')}")
        
        if data.get('patterns_detected'):
            click.echo(click.style('\nPatterns Detected:', fg='cyan'))
            for pattern in data['patterns_detected']:
                click.echo(f"  - {pattern}")
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)
