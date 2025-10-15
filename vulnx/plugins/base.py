from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BasePlugin(ABC):
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = "Base plugin class"
    
    @abstractmethod
    def scan(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        pass
    
    def validate_target(self, target: str) -> bool:
        return True
    
    def get_info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description
        }
    
    def setup(self, **config):
        pass
    
    def teardown(self):
        pass