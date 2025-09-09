from typing import Dict, Type, Set
from .base import QueryHandler
from .handlers.graph_handlers import KnnGraphHandler, PagerankGraphHandler, MetapathGraphHandler
from .handlers.embedding_handlers import (
    VanillaEmbeddingHandler, 
    MetadataEmbeddingHandler, 
    SegCtxEmbeddingHandler, 
    MetadrivenEmbeddingHandler
)


class QueryHandlerFactory:
    """
    Factory class to create appropriate query handlers based on pattern_id.
    
    To register a new pattern:
        QueryHandlerFactory.register_handler("my_pattern", MyPatternHandler)
    
    Or add directly to _handlers dict for built-in patterns.
    """
    
    _handlers: Dict[str, Type[QueryHandler]] = {
        "knn_graph": KnnGraphHandler,
        "pagerank_graph": PagerankGraphHandler,
        "metapath_graph": MetapathGraphHandler,
        "vanilla_embedding": VanillaEmbeddingHandler,
        "metadata_embedding": MetadataEmbeddingHandler,
        "seg_ctx_embedding": SegCtxEmbeddingHandler,
        "metadata_driven_embedding": MetadrivenEmbeddingHandler,
    }
    
    # Pattern type classifications for validation
    _graph_patterns: Set[str] = {
        "knn_graph", 
        "pagerank_graph", 
        "metapath_graph"
    }
    
    _embedding_patterns: Set[str] = {
        "vanilla_embedding", 
        "metadata_embedding", 
        "seg_ctx_embedding", 
        "metadata_driven_embedding"
    }
    
    @classmethod
    def get_handler(cls, pattern_id: str) -> QueryHandler:
        """Get handler instance for the given pattern_id"""
        if pattern_id not in cls._handlers:
            raise ValueError(f"Unknown pattern_id: {pattern_id}. Available patterns: {list(cls._handlers.keys())}")
        
        handler_class = cls._handlers[pattern_id]
        return handler_class()
    
    @classmethod
    def get_available_patterns(cls) -> list[str]:
        """Get list of all available pattern IDs"""
        return list(cls._handlers.keys())
    
    @classmethod
    def register_handler(cls, pattern_id: str, handler_class: Type[QueryHandler]) -> None:
        """
        Register a new pattern handler.
        
        Args:
            pattern_id: Unique identifier for the pattern
            handler_class: Class that implements QueryHandler interface
        """
        if not issubclass(handler_class, QueryHandler):
            raise ValueError(f"Handler class must inherit from QueryHandler")
        
        cls._handlers[pattern_id] = handler_class
    
    @classmethod
    def unregister_handler(cls, pattern_id: str) -> None:
        """Remove a pattern handler from the registry"""
        if pattern_id in cls._handlers:
            del cls._handlers[pattern_id]
    
    @classmethod
    def is_graph_pattern(cls, pattern_id: str) -> bool:
        """Check if a pattern requires graph database"""
        return pattern_id in cls._graph_patterns
    
    @classmethod
    def is_embedding_pattern(cls, pattern_id: str) -> bool:
        """Check if a pattern requires vector database"""
        return pattern_id in cls._embedding_patterns
    
    @classmethod
    def validate_data_source_compatibility(cls, pattern_id: str, 
                                         vector_data_source_id: str = None,
                                         graph_data_source_id: str = None) -> None:
        """
        Validate that the pattern is compatible with the provided data sources.
        
        Args:
            pattern_id: The pattern to validate
            vector_data_source_id: Vector database data source ID (if provided)
            graph_data_source_id: Graph database data source ID (if provided)
            
        Raises:
            ValueError: If pattern and data source types are incompatible
        """
        if pattern_id not in cls._handlers:
            raise ValueError(f"Unknown pattern_id: {pattern_id}")
        
        if cls.is_graph_pattern(pattern_id):
            # Graph patterns cannot use vector databases
            if vector_data_source_id and not graph_data_source_id:
                raise ValueError(f"Graph pattern '{pattern_id}' cannot use vector database. Please select a graph database.")
        
        elif cls.is_embedding_pattern(pattern_id):
            # Embedding patterns cannot use graph databases
            if graph_data_source_id and not vector_data_source_id:
                raise ValueError(f"Embedding pattern '{pattern_id}' cannot use graph database. Please select a vector database.")
    
    @classmethod
    def get_required_data_source_type(cls, pattern_id: str) -> str:
        """
        Get the required data source type for a pattern.
        
        Returns:
            "graph", "vector", or "unknown"
        """
        if pattern_id in cls._graph_patterns:
            return "graph"
        elif pattern_id in cls._embedding_patterns:
            return "vector"
        else:
            return "unknown"