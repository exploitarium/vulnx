import json
import csv
from datetime import datetime
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich import box

class OutputHandler:
    
    def __init__(self):
        self.console = Console()
        self.findings = []
    
    def add_finding(self, tool: str, severity: str, description: str, details: Dict = None):
        finding = {
            "tool": tool,
            "severity": severity,
            "description": description,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
    
    def display_results(self):
        if not self.findings:
            self.console.print("[yellow]No vulnerabilities found.[/yellow]")
            return
        
        table = Table(
            title="Vulnerability Scan Results",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED
        )
        
        table.add_column("Tool", style="cyan", width=12)
        table.add_column("Severity", style="red", width=10)
        table.add_column("Description", style="white")
        table.add_column("Details", style="yellow")
        
        for finding in self.findings:
            severity_color = {
                "critical": "red",
                "high": "bright_red", 
                "medium": "yellow",
                "low": "green",
                "info": "blue"
            }.get(finding["severity"].lower(), "white")
            
            details = finding.get("details", {})
            details_str = "\n".join([f"{k}: {v}" for k, v in details.items()])
            
            table.add_row(
                finding["tool"],
                f"[{severity_color}]{finding['severity']}[/{severity_color}]",
                finding["description"],
                details_str[:100] + "..." if len(details_str) > 100 else details_str
            )
        
        self.console.print(table)
    
    def save_results(self, format: str, filename: str):
        if format == "json":
            with open(f"{filename}.json", "w") as f:
                json.dump(self.findings, f, indent=2)
        elif format == "csv":
            with open(f"{filename}.csv", "w", newline="") as f:
                if self.findings:
                    writer = csv.DictWriter(f, fieldnames=self.findings[0].keys())
                    writer.writeheader()
                    writer.writerows(self.findings)
        elif format == "txt":
            with open(f"{filename}.txt", "w") as f:
                for finding in self.findings:
                    f.write(f"Tool: {finding['tool']}\n")
                    f.write(f"Severity: {finding['severity']}\n")
                    f.write(f"Description: {finding['description']}\n")
                    f.write(f"Details: {finding.get('details', {})}\n")
                    f.write("-" * 50 + "\n")
        
        self.console.print(f"[green]Results saved to {filename}.{format}[/green]")
    
    def create_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        )