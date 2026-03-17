import click
import sys
import psutil
import socket
from tabulate import tabulate
from typing import Dict, Any
from system.core.hardware import get_network_interfaces, get_assigned_interfaces, assign_interface_role

@click.group()
def interfaces():
    """Hardware Port / Interface Management"""
    pass

@interfaces.command()
def detect():
    """Auto-detect available hardware ports"""
    click.echo(click.style('\n=== Hardware Network Interfaces ===\n', fg='cyan', bold=True))
    
    try:
        data = get_network_interfaces()
        if not data:
            click.echo("No physical interfaces detected.")
            return
            
        table_data = []
        for name, details in data.items():
            status_color = 'green' if details['status'] == 'UP' else 'red'
            status_formatted = click.style(details['status'], fg=status_color)
            table_data.append([
                name,
                details['mac'],
                details['ip'],
                details['speed'],
                status_formatted
            ])
            
        click.echo(tabulate(
            table_data,
            headers=['Interface / Port', 'MAC Address', 'IP Address', 'Max Speed', 'Link Status'],
            tablefmt='grid'
        ))
        click.echo(click.style("\nUse 'ngfw interfaces assign <port> --role <ROLE>' to bind security zones.", fg='yellow'))
    except Exception as e:
        click.echo(click.style(f'✗ Detection failed: {e}', fg='red'), err=True)


@interfaces.command()
def show():
    """Show current security mappings for hardware ports"""
    click.echo(click.style('\n=== Security Zone Mappings ===\n', fg='cyan', bold=True))
    try:
        mappings = get_assigned_interfaces()
        if not mappings:
            click.echo("No interface mappings have been defined yet.")
            return
            
        table_data = [[port, role] for port, role in mappings.items()]
        click.echo(tabulate(table_data, headers=['Port', 'Assigned Security Role (Zone)'], tablefmt='grid'))
    except Exception as e:
        click.echo(click.style(f'✗ Failed to read config: {e}', fg='red'), err=True)

@interfaces.command()
@click.argument('port')
@click.option('--role', type=click.Choice(['WAN', 'LAN', 'DMZ', 'MGMT', 'HA'], case_sensitive=False), required=True, help='Security role to assign')
def assign(port: str, role: str):
    """Assign a security role to a physical port"""
    try:
        assign_interface_role(port, role)
        click.echo(click.style(f'✓ Successfully mapped port [{port}] to role [{role.upper()}]', fg='green'))
        
    except Exception as e:
        click.echo(click.style(f'✗ Assignment failed: {e}', fg='red'), err=True)
