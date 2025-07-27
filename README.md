# Code Repair Tool Backend

## Overview

A sophisticated AI-powered backend system for automated vulnerability assessment and code repair recommendations. This FastAPI-based service leverages Large Language Models (LLMs), graph databases, and advanced pattern matching algorithms to analyze vulnerable code, generate intelligent repair recommendations, and evaluate their quality using established security frameworks.

## Table of Contents

- [Architecture](#architecture)
- [Core Features](#core-features)
- [Technology Stack](#technology-stack)
- [System Requirements](#system-requirements)
- [Installation & Setup](#installation--setup)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Assessment Workflow](#assessment-workflow)
- [Pattern Matching System](#pattern-matching-system)
- [Evaluation Framework](#evaluation-framework)
- [Database Schema](#database-schema)
- [Authentication & Security](#authentication--security)
- [Deployment](#deployment)
- [Development](#development)
- [Contributing](#contributing)

## Architecture

The system employs a modular architecture designed for scalability and extensibility:

```
app/
    api/v1/routers/     # API endpoints
    core/               # Core business logic
    schemas/            # Pydantic data models
    tests/              # Test suites
    Dockerfile              # Container configuration
    docker-compose.yaml     # Multi-service orchestration
    pyproject.toml          # Project dependencies
```

### Core Components

- **LLM Integration**: Multi-provider language model support (OpenAI, Groq)
- **Graph Database**: Neo4j knowledge graph for vulnerability relationships
- **Pattern Matching**: Advanced algorithms for contextual code retrieval
- **Evaluation Engine**: Multi-criteria assessment using DeepEval framework
- **Authentication**: JWT-based security with user management
- **Storage Layer**: MongoDB for application data, Neo4j for knowledge graphs

## Core Features

### 1. Intelligent Vulnerability Assessment

- **CWE/CVE Integration**: Standardized vulnerability classification
- **Context-Aware Analysis**: Leverages historical vulnerability data
- **Multi-Model Support**: Configurable LLM backends for diverse use cases

### 2. Advanced Pattern Matching

- **Graph-Based Retrieval**: K-NN, PageRank, and MetaPath algorithms
- **Embedding-Based Matching**: Semantic similarity for code segments
- **Configurable Parameters**: Fine-tunable retrieval strategies

### 3. Comprehensive Evaluation

- **Multi-Criteria Assessment**: Security, functionality, and code quality metrics
- **Automated Scoring**: Consistent evaluation using established frameworks
- **Historical Tracking**: Performance analytics over time

### 4. Enterprise-Ready Security

- **JWT Authentication**: Secure token-based access control
- **Role-Based Access**: Granular permission management
- **Audit Logging**: Comprehensive activity tracking

## Technology Stack

| Component            | Technology              | Purpose                         |
| -------------------- | ----------------------- | ------------------------------- |
| **Framework**        | FastAPI 0.116+          | High-performance async API      |
| **Language**         | Python 3.12+            | Modern language features        |
| **Databases**        | MongoDB + Neo4j         | Document store + Graph database |
| **AI/ML**            | LangChain, OpenAI, Groq | LLM orchestration and inference |
| **Evaluation**       | DeepEval 3.2+           | AI system assessment            |
| **Authentication**   | JWT + bcrypt            | Secure user management          |
| **Containerization** | Docker + uv             | Reproducible deployments        |

## System Requirements

### Development Environment

- Python 3.12 or higher
- MongoDB 4.4+
- Neo4j 5.0+
- 8GB RAM minimum (16GB recommended)
- Docker and Docker Compose

### Production Environment

- 4+ CPU cores
- 16GB RAM minimum
- 100GB storage
- SSL certificates for HTTPS
- Load balancing capabilities

## Installation & Setup

### Using Docker (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd code-repair-backend

# Configure environment
cp .env.example .env
# Edit .env with your configuration

# Start services
docker-compose up -d

# Verify installation
curl http://localhost:8000/health
```

### Local Development

```bash
# Install uv package manager
pip install uv

# Install dependencies
uv sync

# Start development server
uv run fastapi dev main.py

# Run tests
uv run pytest
```

## Configuration

The system uses environment variables for configuration:

### Required Environment Variables

```bash
# Database Configuration
MONGODB_URI=mongodb://localhost:27017
DATABASE_NAME=code_repair_db
NEO4J_URI=neo4j://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password

# Security Configuration
SECRET_KEY=your-256-bit-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# AI Provider Configuration
OPENAI_API_KEY=your_openai_key
GROQ_API_KEY=your_groq_key
```

### Optional Configuration

```bash
# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Performance
MAX_WORKERS=4
REQUEST_TIMEOUT=300

# Features
ENABLE_EVALUATION=true
ENABLE_GRAPH_CACHE=true
```

## API Documentation

### Authentication Endpoints

| Endpoint                | Method | Description         |
| ----------------------- | ------ | ------------------- |
| `/api/v1/auth/register` | POST   | User registration   |
| `/api/v1/auth/login`    | POST   | User authentication |
| `/api/v1/auth/logout`   | POST   | Session termination |

### Assessment Endpoints

| Endpoint                                      | Method | Description                       |
| --------------------------------------------- | ------ | --------------------------------- |
| `/api/v1/assessments/`                        | GET    | List user assessments             |
| `/api/v1/assessments/`                        | POST   | Create assessment                 |
| `/api/v1/assessments/{id}`                    | GET    | Retrieve assessment               |
| `/api/v1/assessments/{id}`                    | PUT    | Update assessment                 |
| `/api/v1/assessments/{id}`                    | DELETE | Delete assessment                 |
| `/api/v1/assessments/generate-recommendation` | POST   | Generate repair recommendation    |
| `/api/v1/assessments/generate-fix`            | POST   | Generate code fix                 |
| `/api/v1/assessments/evaluate`                | POST   | Evaluate recommendation quality   |
| `/api/v1/assessments/store-results`           | POST   | Store complete assessment results |

### Pattern Matching Endpoints

| Endpoint                | Method | Description                 |
| ----------------------- | ------ | --------------------------- |
| `/api/v1/query/execute` | POST   | Execute pattern-based query |
| `/api/v1/patterns/`     | GET    | List available patterns     |
| `/api/v1/patterns/`     | POST   | Create custom pattern       |

### Management Endpoints

| Endpoint            | Method   | Description                    |
| ------------------- | -------- | ------------------------------ |
| `/api/v1/models/`   | GET/POST | LLM model management           |
| `/api/v1/criteria/` | GET/POST | Evaluation criteria management |
| `/api/v1/settings/` | GET/PUT  | User preferences               |

## Assessment Workflow

### Standard Assessment Process

1. **Code Submission**: Submit vulnerable code with CWE/CVE identifiers
2. **Context Retrieval**: Execute pattern matching to gather relevant examples
3. **Recommendation Generation**: Use LLM to generate repair recommendations
4. **Code Fix Generation**: Create actual code fixes based on recommendations
5. **Quality Evaluation**: Assess recommendations using multiple criteria
6. **Result Storage**: Persist complete assessment for future reference

### Example Assessment Request

```python
# Generate Recommendation
recommendation_request = {
    "model_type": "openai",
    "model_id": "gpt-4",
    "vulnerable_code": "SELECT * FROM users WHERE id = '" + user_id + "'",
    "cwe_id": "CWE-89",
    "cve_id": "CVE-2021-44228",
    "retrieved_context": "Historical SQL injection examples and fixes"
}

# Store Complete Results
store_request = {
    "scores": {"security": 0.95, "functionality": 0.88, "readability": 0.92},
    "recommendation": "Use parameterized queries to prevent SQL injection",
    "vulnerable_code": "SELECT * FROM users WHERE id = '" + user_id + "'",
    "fixed_code": "SELECT * FROM users WHERE id = ?",
    "cwe_id": "CWE-89",
    "cve_id": "CVE-2021-44228",
    "model_id": "gpt-4",
    "pattern_id": "knn_graph"
}
```

## Pattern Matching System

### Available Patterns

#### Graph-Based Patterns

1. **KNN Graph (`knn_graph`)**

   - K-nearest neighbor traversal with hop-decay scoring
   - Optimal for finding structurally similar vulnerabilities
   - Parameters: `k` (neighbors), `max_hops` (traversal depth)

2. **PageRank Graph (`pagerank_graph`)**

   - Influence-based node ranking algorithm
   - Identifies most critical vulnerability nodes
   - Parameters: `alpha` (damping), `max_iter` (iterations)

3. **MetaPath Graph (`metapath_graph`)**
   - Structured relationship path traversal
   - Leverages semantic relationships between entities
   - Parameters: `path_length`, `relationship_weights`

#### Embedding-Based Patterns (Future)

4. **Vanilla Embedding**: Basic semantic similarity matching
5. **Metadata Embedding**: Enhanced with vulnerability metadata
6. **Segment Context**: Code segment-aware matching
7. **Meta-driven**: Advanced contextual embeddings

### Pattern Configuration Example

```python
pattern_config = {
    "pattern_id": "knn_graph",
    "parameters": {
        "k": 10,
        "max_hops": 3,
        "decay_factor": 0.8,
        "similarity_threshold": 0.7
    },
    "cwe_id": "CWE-89",
    "limit": 50
}
```

## Evaluation Framework

### Assessment Criteria

The system evaluates recommendations across multiple dimensions:

- **Security Effectiveness**: Vulnerability mitigation completeness
- **Functional Correctness**: Code behavior preservation
- **Code Quality**: Readability and maintainability
- **Performance Impact**: Efficiency considerations
- **Implementation Feasibility**: Practical deployment viability

### Scoring Methodology

- **Scale**: 0.0 to 1.0 (normalized scores)
- **Aggregation**: Weighted average across criteria
- **Benchmarking**: Historical performance baselines
- **Calibration**: Regular model performance validation

### Custom Evaluation Criteria

```python
custom_criteria = {
    "name": "Custom Security Assessment",
    "description": "Domain-specific security evaluation",
    "rubrics": [
        {
            "criterion": "vulnerability_coverage",
            "weight": 0.4,
            "description": "Comprehensive vulnerability addressing"
        },
        {
            "criterion": "code_maintainability",
            "weight": 0.3,
            "description": "Long-term code sustainability"
        }
    ]
}
```

## Database Schema

### MongoDB Collections

#### Assessments Collection

```javascript
{
  "_id": ObjectId,
  "user_id": String,
  "cwe_id": String,
  "cve_id": String,
  "vulnerable_code": String,
  "fixed_code": String,
  "recommendation": String,
  "model_id": String,
  "pattern_id": String,
  "evaluation_scores": {
    "security": Number,
    "functionality": Number,
    "readability": Number
  },
  "date_created": Date,
  "date_modified": Date
}
```

#### Users Collection

```javascript
{
  "_id": ObjectId,
  "email": String,
  "hashed_password": String,
  "full_name": String,
  "is_active": Boolean,
  "date_created": Date,
  "last_login": Date
}
```

### Neo4j Graph Schema

#### Node Types

- **CWE**: Common Weakness Enumeration entities
- **CVE**: Common Vulnerabilities and Exposures
- **CodeExample**: Vulnerable code specimens
- **Fix**: Repair implementations

#### Relationship Types

- **RELATES_TO**: CWE-CVE associations
- **DEMONSTRATES**: CVE-CodeExample links
- **FIXES**: CodeExample-Fix connections
- **SIMILAR_TO**: Cross-entity similarity relationships

## Authentication & Security

### JWT Implementation

- **Token Structure**: Header.Payload.Signature (HS256)
- **Payload Claims**: `sub` (user_id), `exp` (expiration), `iat` (issued_at)
- **Refresh Strategy**: Sliding window expiration
- **Revocation**: Server-side token blacklisting

### Security Best Practices

- **Password Hashing**: bcrypt with configurable rounds
- **Input Validation**: Pydantic schema enforcement
- **SQL Injection Prevention**: Parameterized queries
- **CORS Configuration**: Restricted origin policies
- **Rate Limiting**: Per-endpoint request throttling

### User Management

```python
# User Registration
user_data = {
    "email": "user@example.com",
    "password": "secure_password",
    "full_name": "John Doe"
}

# Authentication
credentials = {
    "username": "user@example.com",
    "password": "secure_password"
}

# Token Usage
headers = {
    "Authorization": "Bearer <jwt_token>"
}
```

## Deployment

### Docker Production Deployment

```yaml
# docker-compose.prod.yml
version: "3.8"
services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
    depends_on:
      - mongodb
      - neo4j
    restart: unless-stopped

  mongodb:
    image: mongo:7
    volumes:
      - mongodb_data:/data/db
    restart: unless-stopped

  neo4j:
    image: neo4j:5
    environment:
      - NEO4J_AUTH=neo4j/production_password
    volumes:
      - neo4j_data:/data
    restart: unless-stopped

volumes:
  mongodb_data:
  neo4j_data:
```

### CI/CD Pipeline

The project includes GitHub Actions workflow for automated deployment:

- **Build**: Docker image creation with uv dependency management
- **Test**: Automated test suite execution
- **Deploy**: VM deployment with health checks
- **Monitoring**: Performance and error tracking

### Health Monitoring

- **Health Endpoint**: `/health` - Basic service status
- **Metrics Endpoint**: `/metrics` - Detailed performance metrics
- **Database Connectivity**: Automatic connection health checks
- **LLM Provider Status**: AI service availability monitoring

## Development

### Code Quality Standards

- **Type Hints**: Comprehensive type annotations
- **Documentation**: Docstring coverage for all public methods
- **Testing**: Unit and integration test coverage >90%
- **Linting**: Black, isort, and flake8 compliance
- **Security**: Bandit security analysis

### Testing Strategy

```bash
# Run all tests
uv run pytest

# Coverage report
uv run pytest --cov=app --cov-report=html

# Integration tests
uv run pytest tests/integration/

# Load testing
uv run pytest tests/load/
```

### Local Development Setup

```bash
# Install development dependencies
uv sync --group dev

# Start development services
docker-compose -f docker-compose.dev.yml up -d

# Run development server with hot reload
uv run fastapi dev main.py --reload

# Database migrations
uv run alembic upgrade head
```

## Contributing

### Development Workflow

1. **Fork Repository**: Create personal fork
2. **Feature Branch**: Create branch from main
3. **Implementation**: Follow coding standards
4. **Testing**: Ensure test coverage
5. **Documentation**: Update relevant docs
6. **Pull Request**: Submit for review

### Code Review Guidelines

- **Functionality**: Feature completeness and correctness
- **Security**: Vulnerability assessment and mitigation
- **Performance**: Efficiency and scalability considerations
- **Maintainability**: Code clarity and documentation
- **Testing**: Adequate test coverage and quality

### Issue Reporting

When reporting issues, include:

- **Environment**: OS, Python version, dependencies
- **Reproduction Steps**: Detailed step-by-step process
- **Expected vs Actual**: Clear behavior description
- **Logs**: Relevant error messages and stack traces

---

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For technical support and questions:

- **Issues**: GitHub Issues tracker
- **Documentation**: In-code documentation and examples
- **Community**: Discussions and feature requests

---

_This documentation is maintained alongside the codebase. For the most current information, refer to the source code and inline documentation._
