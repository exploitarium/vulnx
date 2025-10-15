import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from ..utils.helpers import Helpers

class NmapScanner:
    
    def __init__(self, rate_limit: float = 0.1):
        self.rate_limit = rate_limit
        self.helpers = Helpers()
    
    def scan(self, target: str, scan_type: str = "quick") -> List[Dict[str, Any]]:
        scans = {
            "quick": "-T4 -F",
            "deep": "-sS -sV -sC -A -O",
            "vuln": "--script vuln"
        }
        
        command = f"nmap {scans.get(scan_type, scans['quick'])} {target}"
        
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return self._parse_output(result.stdout)
        except subprocess.TimeoutExpired:
            return [{"error": "Nmap scan timed out"}]
        except Exception as e:
            return [{"error": f"Nmap scan failed: {str(e)}"}]
    
    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        findings = []
        
        lines = output.split('\n')
        for line in lines:
            if 'open' in line and 'port' in line:
                parts = line.split()
                if len(parts) >= 3:
                    findings.append({
                        "type": "open_port",
                        "port": parts[0].split('/')[0],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    })
        
        return findings