from abc import ABC, abstractmethod
from typing import Any, Dict


class QueryHandler(ABC):
    """Base class for all pattern query handlers"""
    
    @abstractmethod
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        """Execute the pattern-specific query logic"""
        pass
    
    def validate_base_params(self, cwe_id: str, cve_id: str) -> None:
        """Validate required base parameters"""
        if not cwe_id or not cve_id:
            raise ValueError("Both cwe_id and cve_id are required")