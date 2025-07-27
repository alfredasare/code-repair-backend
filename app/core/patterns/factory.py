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
    """Factory class to create appropriate query handlers based on pattern_id"""
    
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