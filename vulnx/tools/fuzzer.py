import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
from ..utils.helpers import Helpers

class Fuzzer:
    
    def __init__(self, rate_limit: float = 0.1):
        self.rate_limit = rate_limit
        self.helpers = Helpers()
    
    def fuzz_endpoints(self, base_url: str, wordlist: List[str], threads: int = 10) -> List[Dict[str, Any]]:
        discovered = []
        
        def check_endpoint(endpoint):
            url = f"{base_url.rstrip('/')}/{endpoint}"
            try:
                response = requests.get(url, timeout=10, allow_redirects=False)
                if response.status_code not in [404, 403]:
                    return {
                        "url": url,
                        "status_code": response.status_code,
                        "content_length": len(response.content)
                    }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_endpoint, endpoint): endpoint for endpoint in wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered.append(result)
        
        return discovered