import time
import json
import requests
from typing import List, Dict, Any, Optional
from ..utils.helpers import Helpers, ValidationError

class ZAPScanner:
    
    def __init__(self, zap_host: str = "localhost", zap_port: int = 8080, api_key: str = None):
        self.zap_host = zap_host
        self.zap_port = zap_port
        self.api_key = api_key
        self.base_url = f"http://{zap_host}:{zap_port}"
        self.helpers = Helpers()
        self.logger = self.helpers.setup_logging()
        
    def _zap_request(self, endpoint: str, params: Dict = None) -> Dict[str, Any]:
        if params is None:
            params = {}
        
        if self.api_key:
            params['apikey'] = self.api_key
            
        try:
            response = requests.get(f"{self.base_url}{endpoint}", params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"ZAP API request failed: {str(e)}")
            raise ValidationError(f"ZAP API connection failed: {str(e)}")
    
    def is_accessible(self) -> bool:
        try:
            result = self._zap_request('/JSON/core/view/version')
            return 'version' in result
        except:
            return False
    
    def start_scan(self, target: str, scan_policy: str = "Default Policy") -> str:
        params = {
            'url': target,
            'recurse': True,
            'inScopeOnly': True,
            'scanPolicyName': scan_policy,
            'method': 'GET',
            'postData': ''
        }
        
        result = self._zap_request('/JSON/ascan/action/scan/', params)
        return result.get('scan', '')
    
    def get_scan_progress(self, scan_id: str) -> int:
        result = self._zap_request('/JSON/ascan/view/status/', {'scanId': scan_id})
        return int(result.get('status', 0))
    
    def get_alerts(self, target: str = None, risk_level: str = None) -> List[Dict[str, Any]]:
        params = {}
        if target:
            params['baseurl'] = target
        if risk_level:
            params['riskId'] = self._risk_to_id(risk_level)
            
        result = self._zap_request('/JSON/alert/view/alerts/', params)
        return result.get('alerts', [])
    
    def spider(self, target: str) -> str:
        params = {
            'url': target,
            'maxChildren': 50,
            'recurse': True,
            'contextName': '',
            'subtreeOnly': False
        }
        
        result = self._zap_request('/JSON/spider/action/scan/', params)
        return result.get('scan', '')
    
    def get_spider_progress(self, spider_id: str) -> int:
        result = self._zap_request('/JSON/spider/view/status/', {'scanId': spider_id})
        return int(result.get('status', 0))
    
    def _risk_to_id(self, risk_level: str) -> str:
        risk_map = {
            'high': '3',
            'medium': '2', 
            'low': '1',
            'info': '0'
        }
        return risk_map.get(risk_level.lower(), '')
    
    def scan(self, target: str, scan_policy: str = "Default Policy", 
             wait_for_completion: bool = True, timeout: int = 1800) -> List[Dict[str, Any]]:
        
        if not self.is_accessible():
            raise ValidationError("ZAP is not accessible. Please ensure ZAP is running and API is enabled.")
        
        findings = []
        
        try:
            self.logger.info(f"Starting ZAP scan for {target}")
            
            self.logger.info("Starting spider scan...")
            spider_id = self.spider(target)
            
            if wait_for_completion:
                spider_progress = 0
                while spider_progress < 100:
                    time.sleep(5)
                    spider_progress = self.get_spider_progress(spider_id)
                    self.logger.info(f"Spider progress: {spider_progress}%")
            
            self.logger.info("Starting active scan...")
            scan_id = self.start_scan(target, scan_policy)
            
            if wait_for_completion:
                scan_progress = 0
                start_time = time.time()
                
                while scan_progress < 100:
                    if time.time() - start_time > timeout:
                        self.logger.warning("ZAP scan timeout reached")
                        break
                        
                    time.sleep(10)
                    scan_progress = self.get_scan_progress(scan_id)
                    self.logger.info(f"Active scan progress: {scan_progress}%")
            
            self.logger.info("Retrieving scan results...")
            alerts = self.get_alerts(target)
            
            for alert in alerts:
                finding = self._parse_alert(alert)
                if finding:
                    findings.append(finding)
            
            self.logger.info(f"ZAP scan completed. Found {len(findings)} issues.")
            
        except Exception as e:
            self.logger.error(f"ZAP scan failed: {str(e)}")
            findings.append({
                "error": f"ZAP scan failed: {str(e)}",
                "type": "scan_error",
                "severity": "info"
            })
        
        return findings
    
    def _parse_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        try:
            risk_map = {
                'High': 'high',
                'Medium': 'medium', 
                'Low': 'low',
                'Informational': 'info'
            }
            
            return {
                "type": "zap_finding",
                "tool": "ZAP",
                "severity": risk_map.get(alert.get('risk', 'Info'), 'info'),
                "description": alert.get('alert', 'Unknown alert'),
                "details": {
                    "url": alert.get('url', ''),
                    "parameter": alert.get('param', ''),
                    "attack": alert.get('attack', ''),
                    "evidence": alert.get('evidence', ''),
                    "confidence": alert.get('confidence', ''),
                    "cwe_id": alert.get('cweid', ''),
                    "wasc_id": alert.get('wascid', ''),
                    "solution": alert.get('solution', '')
                }
            }
        except Exception as e:
            self.logger.error(f"Failed to parse ZAP alert: {str(e)}")
            return None
    
    def quick_scan(self, target: str) -> List[Dict[str, Any]]:
        return self.scan(target, "Default Policy", True, 600)
    
    def deep_scan(self, target: str) -> List[Dict[str, Any]]:
        return self.scan(target, "Default Policy", True, 3600)