from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.align import Align

class Banner:
    
    @staticmethod
    def show():
        console = Console()
        
        banner_text = """
[bold red]
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗
██║   ██║██║   ██║██║     ████╗  ██║╚██╗██╔╝
██║   ██║██║   ██║██║     ██╔██╗ ██║ ╚███╔╝ 
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║ ██╔██╗ 
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██╔╝ ██╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
[/bold red]
"""
        
        features = [
            "[bold cyan]•[/bold cyan] Multi-tool Integration",
            "[bold cyan]•[/bold cyan] Web Application Scanning", 
            "[bold cyan]•[/bold cyan] Network Vulnerability Detection",
            "[bold cyan]•[/bold cyan] SQL Injection Testing",
            "[bold cyan]•[/bold cyan] Fuzzing & Endpoint Discovery",
            "[bold cyan]•[/bold cyan] Professional Reporting"
        ]
        
        banner_panel = Panel(
            Align.center(Text.from_markup(banner_text)),
            border_style="red",
            title="[bold white]VULNX SCANNER[/bold white]",
            subtitle="[italic yellow]Advanced Security Assessment Platform[/italic yellow]"
        )
        
        features_panel = Panel(
            "\n".join(features),
            title="[bold green]Core Features[/bold green]",
            border_style="green"
        )
        
        info_panel = Panel(
            "[bold yellow] Usage:[/bold yellow] vulnx scan --target https://example.com\n"
            "[bold blue] Mode:[/bold blue] vulnx scan --target TARGET --mode deep\n"
            "[bold magenta] Report:[/bold magenta] vulnx scan --target TARGET --output report.json",
            title="[bold blue]Quick Start[/bold blue]",
            border_style="blue"
        )
        
        console.print(banner_panel)
        console.print(Columns([features_panel, info_panel]))
        console.print()