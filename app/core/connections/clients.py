from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import torch
from pinecone import Pinecone
from neo4j import GraphDatabase, Driver
from langchain_neo4j import Neo4jGraph
from sentence_transformers import SentenceTransformer
from transformers import AutoModelForMaskedLM, AutoTokenizer


class DatabaseClient(ABC):
    """Base class for all database clients"""
    
    @abstractmethod
    def test_connection(self) -> bool:
        """Test if the connection is working"""
        pass
    
    @abstractmethod
    def close(self):
        """Close the connection"""
        pass


class VectorDatabaseClient(DatabaseClient):
    """Base class for vector database clients"""
    
    @abstractmethod
    def query(self, vector: list, sparse_vector: Dict[str, Any] = None, 
              top_k: int = 10, filter: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Query the vector database"""
        pass


class GraphDatabaseClient(DatabaseClient):
    """Base class for graph database clients"""
    
    @abstractmethod
    def query(self, cypher_query: str, parameters: Dict[str, Any] = None) -> list:
        """Execute a Cypher query"""
        pass


class PineconeClient(VectorDatabaseClient):
    """Pinecone vector database client"""
    
    def __init__(self, api_key: str, environment: Optional[str] = None, 
                 index_names: Dict[str, str] = None):
        self.api_key = api_key
        self.environment = environment
        # Default index mapping for backward compatibility
        self.index_names = index_names or {
            "mitre": "metadata-aug-mitre",
            "bigvul": "metadata-retrieval-bigvul", 
            "cvefixes": "code-fixing-metadata-aug"
        }
        self.pc = Pinecone(api_key=api_key)
        self._indexes = {}
        
        # Initialize indexes
        for index_type, index_name in self.index_names.items():
            try:
                self._indexes[index_type] = self.pc.Index(index_name)
            except Exception as e:
                print(f"Warning: Could not initialize index {index_name}: {e}")
    
    def get_index(self, index_type: str):
        """Get a specific index by type"""
        if index_type not in self._indexes:
            raise ValueError(f"Index type '{index_type}' not configured")
        return self._indexes[index_type]
    
    def query(self, vector: list, sparse_vector: Dict[str, Any] = None, 
              top_k: int = 10, filter: Dict[str, Any] = None, 
              index_type: str = "default", **kwargs) -> Dict[str, Any]:
        """Query the specified Pinecone index"""
        index = self.get_index(index_type)
        
        query_params = {
            "vector": vector,
            "top_k": top_k,
            "include_metadata": True
        }
        
        if sparse_vector:
            query_params["sparse_vector"] = sparse_vector
        if filter:
            query_params["filter"] = filter
        
        return index.query(**query_params)
    
    def test_connection(self) -> bool:
        """Test Pinecone connection"""
        try:
            # Try to list indexes to test connection
            self.pc.list_indexes()
            return True
        except Exception:
            return False
    
    def close(self):
        """Pinecone connections are stateless, nothing to close"""
        pass


class Neo4jClient(GraphDatabaseClient):
    """Neo4j graph database client"""
    
    def __init__(self, uri: str, username: str, password: str, 
                 database: str = "neo4j", **kwargs):
        self.uri = uri
        self.username = username
        self.password = password
        self.database = database
        self.driver: Optional[Driver] = None
        self.langchain_graph: Optional[Neo4jGraph] = None
        self._connect()
    
    def _connect(self):
        """Establish connection to Neo4j"""
        self.driver = GraphDatabase.driver(
            self.uri,
            auth=(self.username, self.password)
        )
        
        # Also create LangChain graph for compatibility
        self.langchain_graph = Neo4jGraph(
            url=self.uri,
            username=self.username,
            password=self.password,
            database=self.database,
            enhanced_schema=True
        )
    
    def query(self, cypher_query: str, parameters: Dict[str, Any] = None) -> list:
        """Execute a Cypher query using the driver"""
        with self.driver.session(database=self.database) as session:
            result = session.run(cypher_query, parameters or {})
            return [record.data() for record in result]
    
    def get_langchain_graph(self) -> Neo4jGraph:
        """Get the LangChain Neo4j graph instance"""
        return self.langchain_graph
    
    def test_connection(self) -> bool:
        """Test Neo4j connection"""
        try:
            with self.driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception:
            return False
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()


class ChromaClient(VectorDatabaseClient):
    """Chroma vector database client (placeholder for future implementation)"""
    
    def __init__(self, host: str, port: int = 8000, auth_token: Optional[str] = None,
                 collection_name: str = "default", **kwargs):
        self.host = host
        self.port = port
        self.auth_token = auth_token
        self.collection_name = collection_name
        # TODO: Initialize Chroma client when needed
        raise NotImplementedError("Chroma client not yet implemented")
    
    def query(self, vector: list, sparse_vector: Dict[str, Any] = None,
              top_k: int = 10, filter: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        raise NotImplementedError("Chroma client not yet implemented")
    
    def test_connection(self) -> bool:
        raise NotImplementedError("Chroma client not yet implemented")
    
    def close(self):
        pass