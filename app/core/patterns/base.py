from abc import ABC, abstractmethod
from typing import Any, Dict


class QueryHandler(ABC):
    """
    Base class for all pattern query handlers.
    
    To create a new pattern handler:
    1. Inherit from this class
    2. Implement execute_query() method
    3. Register in QueryHandlerFactory._handlers
    
    Example:
        class MyPatternHandler(QueryHandler):
            def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
                # Your pattern logic here
                return {
                    "raw_results": your_raw_data,
                    "formatted_results": your_formatted_string
                }
    """
    
    @abstractmethod
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        """
        Execute the pattern-specific query logic.
        
        Args:
            cwe_id: The CWE identifier to query for
            cve_id: The CVE identifier to query for
            **kwargs: Additional pattern-specific parameters
            
        Returns:
            Dict containing:
                - "raw_results": Raw data from your pattern
                - "formatted_results": Human-readable formatted string
        """
        pass
    
    def validate_base_params(self, cwe_id: str, cve_id: str) -> None:
        """Validate required base parameters"""
        if not cwe_id or not cve_id:
            raise ValueError("Both cwe_id and cve_id are required")