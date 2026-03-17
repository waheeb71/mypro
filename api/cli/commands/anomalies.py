import click
import sys
from tabulate import tabulate
from api.cli.core.client import get_client

@click.group()
def anomalies():
    """Anomaly detection"""
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
                anomaly.get('timestamp', 'N/A'),
                anomaly.get('src_ip', 'N/A'),
                f"{anomaly.get('anomaly_score', 0):.3f}",
                '✓' if anomaly.get('is_anomaly') else '✗',
                str(anomaly.get('reason', ''))[:50],
                f"{anomaly.get('confidence', 0):.2f}"
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
