import click
import sys
from api.cli.core.client import get_client

@click.group()
def block():
    """IP blocking management"""
    pass

@block.command()
@click.argument('ip_address')
@click.option('--duration', type=int, default=3600, help='Block duration in seconds (default: 3600)')
def add(ip_address: str, duration: int):
    """Block an IP address"""
    try:
        client = get_client()
        result = client.post(f'block/{ip_address}', params={'duration': duration})
        click.echo(click.style(f'✓ IP {ip_address} blocked until {result["blocked_until"]}', fg='green'))
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)

@block.command()
@click.argument('ip_address')
def remove(ip_address: str):
    """Unblock an IP address"""
    try:
        client = get_client()
        client.delete(f'block/{ip_address}')
        click.echo(click.style(f'✓ IP {ip_address} unblocked', fg='green'))
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)
