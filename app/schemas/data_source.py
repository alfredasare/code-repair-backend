from typing import Optional, Dict, Any, Literal
from datetime import datetime
from pydantic import BaseModel, Field, validator


class DataSourceCredentials(BaseModel):
    """Base class for data source credentials"""
    pass


class PineconeCredentials(DataSourceCredentials):
    api_key: str = Field(..., description="Pinecone API key")
    environment: Optional[str] = Field(None, description="Pinecone environment")


class ChromaCredentials(DataSourceCredentials):
    host: str = Field(..., description="Chroma host URL")
    port: Optional[int] = Field(8000, description="Chroma port")
    auth_token: Optional[str] = Field(None, description="Chroma authentication token")


class Neo4jCredentials(DataSourceCredentials):
    uri: str = Field(..., description="Neo4j connection URI")
    username: str = Field(..., description="Neo4j username")
    password: str = Field(..., description="Neo4j password")


class DataSourceConnectionParams(BaseModel):
    """Connection parameters specific to each provider"""
    pass


class PineconeConnectionParams(DataSourceConnectionParams):
    index_names: Dict[str, str] = Field(..., description="Mapping of index types to index names")


class ChromaConnectionParams(DataSourceConnectionParams):
    collection_name: str = Field(..., description="Chroma collection name")
    distance_metric: Optional[str] = Field("cosine", description="Distance metric for similarity search")


class Neo4jConnectionParams(DataSourceConnectionParams):
    database: Optional[str] = Field("neo4j", description="Neo4j database name")
    max_connection_lifetime: Optional[int] = Field(3600, description="Max connection lifetime in seconds")


class DataSourceCreate(BaseModel):
    name: str = Field(..., description="Human-readable name for the data source")
    db_type: Literal["vector", "graph"] = Field(..., description="Type of database")
    provider: str = Field(..., description="Database provider (e.g., pinecone, chroma, neo4j)")
    credentials: Dict[str, Any] = Field(..., description="Encrypted credentials for the data source")
    connection_params: Dict[str, Any] = Field({}, description="Provider-specific connection parameters")
    is_default: bool = Field(False, description="Whether this is the default data source for its type")
    is_active: bool = Field(True, description="Whether this data source is active")
    
    @validator('provider')
    def validate_provider_type_combination(cls, v, values):
        """Validate that provider matches the db_type"""
        db_type = values.get('db_type')
        
        vector_providers = ['pinecone', 'chroma', 'weaviate', 'qdrant']
        graph_providers = ['neo4j', 'arangodb', 'janusgraph']
        
        if db_type == 'vector' and v not in vector_providers:
            raise ValueError(f"Provider '{v}' is not valid for vector databases. Use one of: {vector_providers}")
        elif db_type == 'graph' and v not in graph_providers:
            raise ValueError(f"Provider '{v}' is not valid for graph databases. Use one of: {graph_providers}")
        
        return v


class DataSourceUpdate(BaseModel):
    name: Optional[str] = Field(None, description="Human-readable name for the data source")
    credentials: Optional[Dict[str, Any]] = Field(None, description="Updated encrypted credentials")
    connection_params: Optional[Dict[str, Any]] = Field(None, description="Updated connection parameters")
    is_default: Optional[bool] = Field(None, description="Whether this is the default data source for its type")
    is_active: Optional[bool] = Field(None, description="Whether this data source is active")


class DataSourceResponse(BaseModel):
    id: str
    name: str
    db_type: Literal["vector", "graph"]
    provider: str
    connection_params: Dict[str, Any]
    is_default: bool
    is_active: bool
    date_created: datetime
    date_modified: datetime
    
    # Note: credentials are not included in response for security


class DataSourceListResponse(BaseModel):
    id: str
    name: str
    db_type: Literal["vector", "graph"]
    provider: str
    is_default: bool
    is_active: bool


class DataSourceTestRequest(BaseModel):
    """Request to test a data source connection"""
    test_type: Optional[str] = Field("basic", description="Type of test to perform (basic, full)")


class DataSourceTestResponse(BaseModel):
    """Response from testing a data source connection"""
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None