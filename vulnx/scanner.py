import asyncio
import time
from typing import List, Dict, Any, Optional
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn

from .tools import NmapScanner, NiktoScanner, SQLMapScanner, ZAPScanner, Fuzzer
from .utils.output import OutputHandler
from .utils.helpers import Helpers, ValidationError

class VulnXScanner:
    
    def __init__(self, output_handler: OutputHandler, zap_config: Dict = None):
        self.output = output_handler
        self.helpers = Helpers()
        self.logger = self.helpers.setup_logging()
        
        self.nmap = NmapScanner()
        self.nikto = NiktoScanner()
        self.sqlmap = SQLMapScanner()
        
        zap_config = zap_config or {}
        self.zap = ZAPScanner(
            zap_host=zap_config.get('host', 'localhost'),
            zap_port=zap_config.get('port', 8080),
            api_key=zap_config.get('api_key')
        )
        
        self.fuzzer = Fuzzer()
        
        self.available_tools = self._check_tool_availability()
    
    def _check_tool_availability(self) -> Dict[str, bool]:
        import shutil
        
        tools = {
            'nmap': shutil.which('nmap') is not None,
            'nikto': shutil.which('nikto') is not None,
            'sqlmap': shutil.which('sqlmap') is not None,
            'zap': self.zap.is_accessible(),
            'fuzzer': True  # Built-in tool, always available
        }
        
        for tool, available in tools.items():
            if not available:
                self.logger.warning(f"Tool {tool} is not available")
            else:
                self.logger.info(f"Tool {tool} is available")
        
        return tools
    
    def scan(self, target: str, scan_profile: str = "quick", 
             tools: List[str] = None, **kwargs) -> Dict[str, Any]:
        
        target_info = self.helpers.validate_target(target)
        validated_target = target_info["url"]
        
        self.logger.info(f"Starting {scan_profile} scan for {validated_target}")
        
        if tools is None:
            if scan_profile == "quick":
                tools = ["nmap", "nikto"]
            elif scan_profile == "deep":
                tools = ["nmap", "nikto", "fuzzer", "sqlmap"]
            else:  # full
                tools = ["nmap", "nikto", "sqlmap", "zap", "fuzzer"]
        
        available_tools = [tool for tool in tools if self.available_tools.get(tool, False)]
        unavailable_tools = [tool for tool in tools if not self.available_tools.get(tool, False)]
        
        if unavailable_tools:
            self.logger.warning(f"Unavailable tools skipped: {', '.join(unavailable_tools)}")
        
        results = {}
        total_tasks = len(available_tools)
        
        with self.output.create_progress() as progress:
            main_task = progress.add_task(
                f"[bold blue]Scanning {validated_target}...", 
                total=total_tasks
            )
            
            if "nmap" in available_tools:
                task = progress.add_task("[cyan]Network mapping...", total=100)
                try:
                    nmap_results = self.nmap.scan(validated_target, scan_profile)
                    for finding in nmap_results:
                        if "error" not in finding:
                            self.output.add_finding(
                                "Nmap", 
                                "info", 
                                f"Open port: {finding.get('port', 'unknown')} - {finding.get('service', 'unknown')}",
                                finding
                            )
                    progress.update(task, completed=100)
                except Exception as e:
                    self.logger.error(f"Nmap scan failed: {str(e)}")
                    self.output.add_finding("Nmap", "info", f"Scan failed: {str(e)}")
                progress.update(main_task, advance=1)
            
            if "nikto" in available_tools:
                task = progress.add_task("[green]Web server analysis...", total=100)
                try:
                    nikto_results = self.nikto.scan(validated_target)
                    for finding in nikto_results:
                        if "error" not in finding:
                            self.output.add_finding("Nikto", "medium", finding["description"], finding)
                    progress.update(task, completed=100)
                except Exception as e:
                    self.logger.error(f"Nikto scan failed: {str(e)}")
                    self.output.add_finding("Nikto", "info", f"Scan failed: {str(e)}")
                progress.update(main_task, advance=1)
            
            if "sqlmap" in available_tools:
                task = progress.add_task("[red]SQL injection testing...", total=100)
                try:
                    sqlmap_results = self.sqlmap.scan(validated_target, level=2 if scan_profile == "deep" else 1)
                    for finding in sqlmap_results:
                        if "error" not in finding:
                            self.output.add_finding("SQLMap", "high", finding["description"], finding)
                    progress.update(task, completed=100)
                except Exception as e:
                    self.logger.error(f"SQLMap scan failed: {str(e)}")
                    self.output.add_finding("SQLMap", "info", f"Scan failed: {str(e)}")
                progress.update(main_task, advance=1)
            
            if "zap" in available_tools and scan_profile in ["full", "deep"]:
                task = progress.add_task("[magenta]Web application testing...", total=100)
                try:
                    if scan_profile == "deep":
                        zap_results = self.zap.quick_scan(validated_target)
                    else:
                        zap_results = self.zap.deep_scan(validated_target)
                    
                    for finding in zap_results:
                        if "error" not in finding:
                            self.output.add_finding(
                                finding.get("tool", "ZAP"),
                                finding.get("severity", "info"),
                                finding.get("description", "Unknown finding"),
                                finding.get("details", {})
                            )
                    progress.update(task, completed=100)
                except Exception as e:
                    self.logger.error(f"ZAP scan failed: {str(e)}")
                    self.output.add_finding("ZAP", "info", f"Scan failed: {str(e)}")
                progress.update(main_task, advance=1)
            
            if "fuzzer" in available_tools:
                task = progress.add_task("[yellow]Endpoint discovery...", total=100)
                try:
                    common_paths = [
                        "admin", "login", "config", "backup", "api", "test", 
                        "debug", "phpinfo", "wp-admin", "administrator",
                        "uploads", "images", "css", "js", "src", "source",
                        "backup", "old", "temp", "tmp", "logs"
                    ]
                    fuzz_results = self.fuzzer.fuzz_endpoints(
                        validated_target, 
                        common_paths,
                        threads=kwargs.get('threads', 10)
                    )
                    for finding in fuzz_results:
                        self.output.add_finding(
                            "Fuzzer", 
                            "info", 
                            f"Discovered endpoint: {finding['url']} (Status: {finding['status_code']})",
                            finding
                        )
                    progress.update(task, completed=100)
                except Exception as e:
                    self.logger.error(f"Fuzzing failed: {str(e)}")
                    self.output.add_finding("Fuzzer", "info", f"Scan failed: {str(e)}")
                progress.update(main_task, advance=1)
        
        return {
            "status": "completed", 
            "findings_count": len(self.output.findings),
            "target": validated_target,
            "profile": scan_profile,
            "tools_used": available_tools,
            "timestamp": time.time()
        }