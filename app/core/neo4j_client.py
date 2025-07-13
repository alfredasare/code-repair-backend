import os
from typing import Optional
from neo4j import GraphDatabase, Driver
from langchain_neo4j import Neo4jGraph
from app.core.config import settings


class Neo4jDriver:
    def __init__(self):
        self.driver: Optional[Driver] = None
        self._connect()
    
    def _connect(self):
        self.driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
    
    def close(self):
        if self.driver:
            self.driver.close()
    
    def get_driver(self) -> Driver:
        if not self.driver:
            self._connect()
        return self.driver
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class Neo4jLangchain:
    def __init__(self):
        self.graph: Optional[Neo4jGraph] = None
        self._connect()
    
    def _connect(self):
        self.graph = Neo4jGraph(
            url=settings.neo4j_uri,
            username=settings.neo4j_user,
            password=settings.neo4j_password,
            enhanced_schema=True
        )
    
    def get_graph(self) -> Neo4jGraph:
        if not self.graph:
            self._connect()
        return self.graph


neo4j_driver: Optional[Neo4jDriver] = None
neo4j_graph: Optional[Neo4jLangchain] = None

def get_neo4j_driver() -> Neo4jDriver:
    global neo4j_driver
    if not neo4j_driver:
        neo4j_driver = Neo4jDriver()
    return neo4j_driver

def get_neo4j_graph() -> Neo4jLangchain:
    global neo4j_graph
    if not neo4j_graph:
        neo4j_graph = Neo4jLangchain()
    return neo4j_graph