import click
import json
import sys
from tabulate import tabulate
from typing import Optional
from api.cli.core.client import get_client

@click.group()
def rules():
    """Firewall rules management"""
    pass

@rules.command()
@click.option('--format', type=click.Choice(['table', 'json']), default='table', help='Output format')
def list(format: str):
    """List all firewall rules"""
    try:
        client = get_client()
        data = client.get('rules')
        
        if format == 'json':
            click.echo(json.dumps(data, indent=2))
        else:
            if not data:
                click.echo('No rules found')
                return
            
            table_data = [
                [
                    rule['rule_id'],
                    rule.get('src_ip', '*'),
                    rule.get('dst_ip', '*'),
                    rule.get('dst_port', '*'),
                    rule.get('protocol', '*'),
                    rule['action'],
                    rule['priority'],
                    '✓' if rule['enabled'] else '✗'
                ]
                for rule in data
            ]
            click.echo(tabulate(
                table_data,
                headers=['Rule ID', 'Source IP', 'Dest IP', 'Port', 'Protocol', 'Action', 'Priority', 'Enabled'],
                tablefmt='grid'
            ))
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)

@rules.command()
@click.option('--src-ip', help='Source IP (CIDR notation)')
@click.option('--dst-ip', help='Destination IP (CIDR notation)')
@click.option('--dst-port', type=int, help='Destination port')
@click.option('--protocol', type=click.Choice(['TCP', 'UDP', 'ICMP', 'ALL']), help='Protocol')
@click.option('--action', type=click.Choice(['ALLOW', 'BLOCK', 'THROTTLE']), required=True, help='Action')
@click.option('--priority', type=int, default=100, help='Priority (1-1000, default: 100)')
def add(src_ip: Optional[str], dst_ip: Optional[str], dst_port: Optional[int], 
        protocol: Optional[str], action: str, priority: int):
    """Add a new firewall rule"""
    try:
        if not any([src_ip, dst_ip, dst_port]):
            click.echo(click.style('✗ At least one of --src-ip, --dst-ip, or --dst-port must be specified', fg='red'), err=True)
            sys.exit(1)
        
        client = get_client()
        rule_data = {'action': action, 'priority': priority, 'enabled': True}
        
        if src_ip: rule_data['src_ip'] = src_ip
        if dst_ip: rule_data['dst_ip'] = dst_ip
        if dst_port: rule_data['dst_port'] = dst_port
        if protocol: rule_data['protocol'] = protocol
        
        result = client.post('rules', json=rule_data)
        click.echo(click.style(f'✓ Rule created: {result["rule_id"]}', fg='green'))
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)

@rules.command()
@click.argument('rule_id')
def delete(rule_id: str):
    """Delete a firewall rule"""
    try:
        if not click.confirm(f'Delete rule {rule_id}?'):
            click.echo('Cancelled')
            return
        
        client = get_client()
        client.delete(f'rules/{rule_id}')
        click.echo(click.style(f'✓ Rule {rule_id} deleted', fg='green'))
    except Exception as e:
        click.echo(click.style(f'✗ Error: {e}', fg='red'), err=True)
        sys.exit(1)
