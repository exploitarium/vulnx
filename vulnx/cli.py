#!/usr/bin/env python3

import click
from rich.console import Console

from .utils.banner import Banner
from .utils.output import OutputHandler
from .scanner import VulnXScanner
from .utils.helpers import ValidationError

@click.group(invoke_without_command=True)
@click.pass_context
@click.option('--version', is_flag=True, help='Show version information')
def cli(ctx, version):
    if version:
        click.echo("VulnX v1.0.0")
        return
    
    if ctx.invoked_subcommand is None:
        Banner.show()

@cli.command()
@click.option('--target', '-t', required=True, help='Target URL or IP address')
@click.option('--profile', '-p', default='quick', 
              type=click.Choice(['quick', 'deep', 'full']), 
              help='Scan profile')
@click.option('--output', '-o', type=click.Choice(['json', 'csv', 'txt']), 
              help='Output format')
@click.option('--output-file', '-f', help='Output filename (without extension)')
@click.option('--tools', help='Comma-separated list of tools to use')
@click.option('--rate-limit', default=0.1, help='Rate limiting delay between requests')
@click.option('--threads', default=10, help='Number of threads for fuzzing')
@click.option('--zap-host', default='localhost', help='OWASP ZAP host')
@click.option('--zap-port', default=8080, help='OWASP ZAP port')
@click.option('--zap-api-key', help='OWASP ZAP API key')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(target, profile, output, output_file, tools, rate_limit, threads,
         zap_host, zap_port, zap_api_key, verbose):
    
    console = Console()
    
    try:
        output_handler = OutputHandler()
        
        zap_config = {
            'host': zap_host,
            'port': zap_port,
            'api_key': zap_api_key
        }
        
        scanner = VulnXScanner(output_handler, zap_config)
        
        tools_list = tools.split(',') if tools else None
        
        with console.status(f"[bold green]Scanning {target} with {profile} profile...") as status:
            result = scanner.scan(
                target=target,
                scan_profile=profile,
                tools=tools_list,
                rate_limit=rate_limit,
                threads=threads
            )
        
        console.print("\n[bold green]Scan Completed![/bold green]")
        console.print(f"[bold blue]Tools used: {', '.join(result['tools_used'])}[/bold blue]")
        output_handler.display_results()
        
        if output and output_file:
            output_handler.save_results(output, output_file)
        elif output:
            import re
            safe_target = re.sub(r'[^a-zA-Z0-9]', '_', target)
            output_handler.save_results(output, f"vulnx_scan_{safe_target}")
            
    except ValidationError as e:
        console.print(f"[red]Error: {str(e)}[/red]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())

@cli.command()
@click.option('--target', '-t', required=True, help='Target to fuzz')
@click.option('--wordlist', '-w', help='Path to wordlist file')
@click.option('--threads', default=10, help='Number of threads')
def fuzz(target, wordlist, threads):
    console = Console()
    
    try:
        from .tools import Fuzzer
        fuzzer = Fuzzer()
        
        if not wordlist:
            wordlist = ["admin", "login", "api", "config", "backup", "test", 
                       "debug", "phpinfo", "wp-admin", "administrator"]
        else:
            with open(wordlist, 'r') as f:
                wordlist = [line.strip() for line in f.readlines()]
        
        console.print(f"[yellow]Fuzzing {target} with {len(wordlist)} words...[/yellow]")
        
        results = fuzzer.fuzz_endpoints(target, wordlist, threads)
        
        if results:
            console.print(f"[green]Discovered {len(results)} endpoints:[/green]")
            for result in results:
                console.print(f"  {result['url']} - {result['status_code']}")
        else:
            console.print("[yellow]No endpoints discovered[/yellow]")
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

@cli.command()
def plugins():
    console = Console()
    console.print("[bold blue]Available Plugins:[/bold blue]")
    console.print("  • [cyan]nmap[/cyan] - Network port scanning")
    console.print("  • [cyan]nikto[/cyan] - Web server scanning") 
    console.print("  • [cyan]sqlmap[/cyan] - SQL injection testing")
    console.print("  • [cyan]zap[/cyan] - OWASP ZAP integration")
    console.print("  • [cyan]fuzzer[/cyan] - Endpoint discovery")

def main():
    """Main entry point"""
    cli(prog_name='vulnx')

if __name__ == '__main__':
    main()
