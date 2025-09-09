from typing import Dict, Any, Optional
from .clients import VectorDatabaseClient, GraphDatabaseClient, PineconeClient, Neo4jClient, ChromaClient
from .encryption import credential_encryption
from app.core.storage import data_source_storage


class ConnectionManager:
    """Manages database connections based on data source configurations"""
    
    def __init__(self):
        self._vector_clients: Dict[str, VectorDatabaseClient] = {}
        self._graph_clients: Dict[str, GraphDatabaseClient] = {}
    
    def get_vector_client(self, data_source_id: str) -> VectorDatabaseClient:
        """Get or create a vector database client for the given data source"""
        if data_source_id in self._vector_clients:
            return self._vector_clients[data_source_id]
        
        # Load data source configuration
        data_source = data_source_storage.find_by_id(data_source_id)
        if not data_source:
            raise ValueError(f"Data source with ID {data_source_id} not found")
        
        if data_source["db_type"] != "vector":
            raise ValueError(f"Data source {data_source_id} is not a vector database")
        
        if not data_source["is_active"]:
            raise ValueError(f"Data source {data_source_id} is not active")
        
        # Decrypt credentials
        credentials = credential_encryption.decrypt_credentials(data_source["credentials"])
        connection_params = data_source.get("connection_params", {})
        
        # Create client based on provider
        provider = data_source["provider"]
        
        if provider == "pinecone":
            client = PineconeClient(
                api_key=credentials["api_key"],
                environment=credentials.get("environment"),
                index_names=connection_params.get("index_names", {})
            )
        elif provider == "chroma":
            client = ChromaClient(
                host=credentials["host"],
                port=credentials.get("port", 8000),
                auth_token=credentials.get("auth_token"),
                collection_name=connection_params.get("collection_name", "default")
            )
        else:
            raise ValueError(f"Unsupported vector database provider: {provider}")
        
        # Cache the client
        self._vector_clients[data_source_id] = client
        return client
    
    def get_graph_client(self, data_source_id: str) -> GraphDatabaseClient:
        """Get or create a graph database client for the given data source"""
        if data_source_id in self._graph_clients:
            return self._graph_clients[data_source_id]
        
        # Load data source configuration
        data_source = data_source_storage.find_by_id(data_source_id)
        if not data_source:
            raise ValueError(f"Data source with ID {data_source_id} not found")
        
        if data_source["db_type"] != "graph":
            raise ValueError(f"Data source {data_source_id} is not a graph database")
        
        if not data_source["is_active"]:
            raise ValueError(f"Data source {data_source_id} is not active")
        
        # Decrypt credentials
        credentials = credential_encryption.decrypt_credentials(data_source["credentials"])
        connection_params = data_source.get("connection_params", {})
        
        # Create client based on provider
        provider = data_source["provider"]
        
        if provider == "neo4j":
            client = Neo4jClient(
                uri=credentials["uri"],
                username=credentials["username"],
                password=credentials["password"],
                database=connection_params.get("database", "neo4j"),
                max_connection_lifetime=connection_params.get("max_connection_lifetime", 3600)
            )
        else:
            raise ValueError(f"Unsupported graph database provider: {provider}")
        
        # Cache the client
        self._graph_clients[data_source_id] = client
        return client
    
    def get_default_vector_client(self) -> VectorDatabaseClient:
        """Get the default vector database client"""
        default_source = data_source_storage.find_default_by_type("vector")
        if not default_source:
            raise ValueError("No default vector database configured")
        
        return self.get_vector_client(default_source["id"])
    
    def get_default_graph_client(self) -> GraphDatabaseClient:
        """Get the default graph database client"""
        default_source = data_source_storage.find_default_by_type("graph")
        if not default_source:
            raise ValueError("No default graph database configured")
        
        return self.get_graph_client(default_source["id"])
    
    def test_connection(self, data_source_id: str) -> Dict[str, Any]:
        """Test connection to a data source"""
        try:
            data_source = data_source_storage.find_by_id(data_source_id)
            if not data_source:
                return {"success": False, "message": "Data source not found"}
            
            if data_source["db_type"] == "vector":
                client = self.get_vector_client(data_source_id)
            elif data_source["db_type"] == "graph":
                client = self.get_graph_client(data_source_id)
            else:
                return {"success": False, "message": "Unknown database type"}
            
            success = client.test_connection()
            return {
                "success": success,
                "message": "Connection successful" if success else "Connection failed"
            }
        
        except Exception as e:
            return {"success": False, "message": f"Connection test failed: {str(e)}"}
    
    def close_all_connections(self):
        """Close all cached connections"""
        for client in self._vector_clients.values():
            client.close()
        for client in self._graph_clients.values():
            client.close()
        
        self._vector_clients.clear()
        self._graph_clients.clear()
    
    def remove_cached_connection(self, data_source_id: str):
        """Remove a cached connection (useful when data source is updated)"""
        if data_source_id in self._vector_clients:
            self._vector_clients[data_source_id].close()
            del self._vector_clients[data_source_id]
        
        if data_source_id in self._graph_clients:
            self._graph_clients[data_source_id].close()
            del self._graph_clients[data_source_id]


# Global connection manager instance
connection_manager = ConnectionManager()