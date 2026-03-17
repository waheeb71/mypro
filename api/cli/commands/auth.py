import click
import sys
from api.cli.core.client import NGFWClient, DEFAULT_API_URL, save_config, load_config, CONFIG_FILE

@click.group()
def auth():
    """Authentication commands"""
    pass

@auth.command()
@click.option('--username', prompt=True, help='Username')
@click.option('--password', prompt=True, hide_input=True, help='Password')
@click.option('--api-url', default=DEFAULT_API_URL, help='API URL')
def login(username: str, password: str, api_url: str):
    """Login to NGFW API"""
    try:
        client = NGFWClient(api_url)
        token = client.login(username, password)
        save_config({'api_url': api_url, 'token': token, 'username': username})
        click.echo(click.style('✓ Login successful!', fg='green'))
    except Exception as e:
        click.echo(click.style(f'✗ Login failed: {e}', fg='red'), err=True)
        sys.exit(1)

@auth.command()
def logout():
    """Logout from NGFW API"""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        click.echo(click.style('✓ Logged out successfully', fg='green'))
    else:
        click.echo('Not logged in')

@auth.command()
def whoami():
    """Show current user information"""
    config = load_config()
    if 'username' in config:
        click.echo(f"Logged in as: {config['username']}")
        click.echo(f"API URL: {config.get('api_url', DEFAULT_API_URL)}")
    else:
        click.echo('Not logged in')
