from typing import Dict, Type
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