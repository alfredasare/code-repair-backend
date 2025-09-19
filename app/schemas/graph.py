from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # "CWE", "CVE", "CODE_EXAMPLE"
    properties: Dict[str, Any] = {}
    size: Optional[float] = 10.0
    color: Optional[str] = None

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str  # "HAS_VULNERABILITY", "HAS_CODE_EXAMPLE", etc.
    weight: Optional[float] = 1.0
    label: Optional[str] = None

class GraphVisualizationData(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    metadata: Dict[str, Any] = {}
