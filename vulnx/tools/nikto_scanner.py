import subprocess
import re
from typing import List, Dict, Any

class NiktoScanner:
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        command = f"nikto -h {target} -Format txt"
        
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=600
            )
            
            return self._parse_output(result.stdout)
        except Exception as e:
            return [{"error": f"Nikto scan failed: {str(e)}"}]
    
    def _parse_output(self, output: str) -> List[Dict[str, Any]]:
        findings = []
        
        lines = output.split('\n')
        for line in lines:
            if '+ ' in line and 'Server:' not in line:
                cleaned = line.replace('+ ', '').strip()
                if cleaned:
                    findings.append({
                        "type": "web_vulnerability",
                        "description": cleaned,
                        "severity": "medium"  # Nikto findings are typically medium
                    })
        
        return findings