import click
import sys
from tabulate import tabulate
from api.cli.core.client import get_client

@click.group()
def stats():
    """Traffic statistics"""
    pass

@stats.command()
@click.option('--window', default=300, help='Time window in seconds (default: 300)')
def show(window: int):
    """Show traffic statistics"""
    try:
        client = get_client()
        data = client.get('statistics', params={'time_window': window})
        
        click.echo(click.style('\n=== Traffic Statistics ===\n', fg='cyan', bold=True))
        click.echo(f"Timestamp: {data['timestamp']}")
        click.echo(f"\nTotal Packets: {data['total_packets']:,}")
        click.echo(f"Total Bytes: {data['total_bytes']:,}")
        click.echo(f"Blocked: {data['blocked_packets']:,}")
        click.echo(f"Allowed: {data['allowed_packets']:,}")
        click.echo(f"\nUnique Sources: {data['unique_sources']:,}")
        click.echo(f"Unique Destinations: {data['unique_destinations']:,}")
        
        click.echo(click.style('\nTop Protocols:', fg='cyan'))
        for proto, count in data['top_protocols'].items():
            click.echo(f"  {proto}: {count:,}")
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)


@click.group()
def anomalies():
    """Anomaly detection output"""
    pass

@anomalies.command()
@click.option('--limit', type=int, default=20, help='Maximum results (default: 20)')
def list(limit: int):
    """List recent anomalies"""
    try:
        client = get_client()
        data = client.get('anomalies', params={'limit': limit})
        
        if not data:
            click.echo('No anomalies detected')
            return
            
        table_data = [
            [
                anomaly['timestamp'],
                anomaly['src_ip'],
                f"{anomaly['anomaly_score']:.3f}",
                '✓' if anomaly['is_anomaly'] else '✗',
                anomaly['reason'][:50],
                f"{anomaly['confidence']:.2f}"
            ]
            for anomaly in data
        ]
        
        click.echo(tabulate(
            table_data,
            headers=['Timestamp', 'Source IP', 'Score', 'Anomaly', 'Reason', 'Confidence'],
            tablefmt='grid'
        ))
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)


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
        click.echo(f"Reputation Score: {data['reputation_score']:.1f}")
        click.echo(f"Total Connections: {data['total_connections']:,}")
        click.echo(f"First Seen: {data['first_seen']}")
        click.echo(f"Last Seen: {data['last_seen']}")
        
        if data['patterns_detected']:
            click.echo(click.style('\nPatterns Detected:', fg='cyan'))
            for pattern in data['patterns_detected']:
                click.echo(f"  - {pattern}")
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)
