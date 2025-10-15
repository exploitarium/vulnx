import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Union
import logging

class ValidationError(Exception):
    pass

class Helpers:
    
    @staticmethod
    def validate_target(target: str) -> dict:
        if not target:
            raise ValidationError("Target cannot be empty")
        
        target = target.strip()
        
        try:
            ipaddress.ip_address(target)
            return {"type": "ip", "url": f"http://{target}"}
        except ValueError:
            pass
        
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        try:
            parsed = urlparse(target)
            if not parsed.netloc:
                raise ValidationError("Invalid target format")
            
            return {"type": "url", "url": target}
        except Exception as e:
            raise ValidationError(f"Invalid target: {str(e)}")
    
    @staticmethod
    def setup_logging(level: str = "INFO") -> logging.Logger:
        logger = logging.getLogger("vulnx")
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        logger.setLevel(getattr(logging, level.upper()))
        return logger
    
    @staticmethod
    def rate_limit(delay: float):
        import time
        def decorator(func):
            def wrapper(*args, **kwargs):
                time.sleep(delay)
                return func(*args, **kwargs)
            return wrapper
        return decorator