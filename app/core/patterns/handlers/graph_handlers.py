from typing import Any, Dict
from ..base import QueryHandler
from app.core.neo4j_client import get_neo4j_graph


class KnnGraphHandler(QueryHandler):
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        self.validate_base_params(cwe_id, cve_id)
        
        # Extract optional parameters with defaults
        max_hops = kwargs.get('max_hops', 2)
        alpha = kwargs.get('alpha', 0.8)
        top_k = kwargs.get('top_k', 10)
        
        # Query the graph
        raw_results = self._query_graph(cwe_id, cve_id, max_hops, alpha, top_k)
        
        # Format the results
        formatted_results = self._build_context(raw_results)
        
        return {
            "raw_results": raw_results,
            "formatted_results": formatted_results
        }
    
    def _query_graph(self, cwe_id: str, cve_id: str, max_hops: int, alpha: float, top_k: int):
        """Query the Neo4j graph using KNN approach"""
        graph = get_neo4j_graph().get_graph()
        
        return graph.query(
            """
            // Input parameters: $cweId (string), $topK (integer, e.g., 5), $alpha (float, e.g., 0.7)
            // $alpha should likely be between 0 and 1 for decay.

            MATCH (start:CWE {id: $cweId})

            // Find all paths (0-2 hops) to potential target CWEs
            OPTIONAL MATCH path = (start)-[rels:HAS_PARENT|PEER_WITH|RELATES_TO*0..2]-(targetCwe:CWE)

            // Ensure a target was found (handles disconnected start node)
            WHERE targetCwe IS NOT NULL

            // Calculate path length (hops) and get the list of relationship types for this specific path
            // Use relationships(path) function to get the list of relationships in the path
            // Use type(r) to get the string name of each relationship type
            // For a 0-hop path, relationships(path) is empty, so relTypes will be []
            WITH targetCwe, path, length(path) AS hops, [r IN relationships(path) | type(r)] AS relTypes

            // --- Select Shortest Path and its Types ---
            // We need the types associated with the shortest path to the targetCwe.
            // First, order by hops ASC. This ensures that when we collect, the details for the shortest path(s) come first.
            ORDER BY hops ASC
            // Collect all path details (hops and types) for each targetCwe
            WITH targetCwe, collect({hops: hops, types: relTypes}) AS pathData
            // The first element in the collected list `pathData` corresponds to a path with the minimum hops
            // because we ordered by hops ASC before collecting. Extract min hops and the types from this first element.
            WITH targetCwe, pathData[0].hops AS minHops, pathData[0].types AS shortestPathTypes

            // Calculate the hop-decayed score: score = alpha ^ minHops
            WITH targetCwe, minHops, shortestPathTypes, $alpha ^ minHops AS score

            // Check if this targetCwe (reached via shortest path) has the required CVE -> Example chain
            OPTIONAL MATCH (targetCwe)-[:HAS_VULNERABILITY]->(cve:CVE)-[:HAS_CODE_EXAMPLE]->(ex:CODE_EXAMPLE)

            // Keep only those targetCwes that have the full chain
            WHERE cve IS NOT NULL AND ex IS NOT NULL

            // Select ONE representative CVE/Example pair per targetCwe
            // Prioritize the specific CVE if it matches, otherwise pick deterministically
            WITH targetCwe, minHops, shortestPathTypes, score, cve, ex
            ORDER BY CASE WHEN cve.id = $cveId THEN 0 ELSE 1 END, cve.id, ex.id
            WITH targetCwe, minHops, shortestPathTypes, score, head(collect({cve: cve, example: ex})) AS selectedPair

            // Order results primarily by the calculated score (DESCENDING - higher score is better)
            ORDER BY score DESC, targetCwe.id ASC // Secondary sort for stability

            // Limit to the desired number of top results
            LIMIT $topK

            // --- Add Rank (based on the score ordering) ---
            // Collect the ordered & limited results into a list, including the shortest path types
            WITH collect({
                targetCwe: targetCwe,
                selectedPair: selectedPair,
                hops: minHops,
                score: score,
                relationTypes: shortestPathTypes // Include the types here
            }) AS orderedResults

            // Unwind the list using an index (0-based)
            UNWIND range(0, size(orderedResults) - 1) AS idx

            // Access each item and calculate the rank (1-based)
            WITH orderedResults[idx] AS item, idx + 1 AS rank

            // --- Format Final Output ---
            RETURN {
                rank: rank, // The final rank (1, 2, 3...) based on score
                score: item.score, // The calculated hop-decayed score
                cwe: properties(item.targetCwe),
                cve: properties(item.selectedPair.cve),
                codeExample: properties(item.selectedPair.example),
                hops: item.hops, // The minimum hops used to calculate the score
                relationTypes: item.relationTypes // List of relationship types in the shortest path
            } AS result
            """,
            {
                "alpha": alpha,
                "topK": top_k,
                "cweId": cwe_id,
                "cveId": cve_id,
                "maxHops": max_hops
            }
        )
    
    def _build_context(self, results):
        """Build context string for LLM prompt based on search results"""
        context_parts = []
        related_results_pool = []
        target_cwe_found = False

        # --- 1. Find Target CWE (score=1.0) and separate others ---
        for item in results:
            record = item.get('result', {})
            if record.get('score') == 1.0 and not target_cwe_found:
                cwe = record.get('cwe')
                if cwe:
                    context_parts.append("Target CWE Information:")
                    context_parts.append(f"  ID: {cwe.get('id', 'N/A')}")
                    context_parts.append(f"  Name: {cwe.get('name', 'N/A')}")
                    context_parts.append(f"  Description: {cwe.get('description', 'N/A')}")
                    
                    # Add CVE Info for target CWE
                    cve = record.get('cve')
                    if cve:
                        context_parts.append("  CVE Information:")
                        context_parts.append(f"    ID: {cve.get('id', 'N/A')}")
                        context_parts.append(f"    Description: {cve.get('description', 'N/A')}")
                    
                    # Add Code Example for target CWE
                    code_example = record.get('codeExample')
                    if code_example:
                        context_parts.append("  Code Example:")
                        context_parts.append("    Code Before Fix:")
                        context_parts.append(f"    ```\n{code_example.get('code_before', '# No code provided')}\n    ```")
                        context_parts.append("    Code After Fix:")
                        context_parts.append(f"    ```\n{code_example.get('code_after', '# No code provided')}\n    ```")
                    
                    context_parts.append("-" * 80 + "\n")
                    target_cwe_found = True
                # Do not add the target CWE item to the related pool
            elif record:  # Add non-target items to the pool for potential examples
                related_results_pool.append(record)

        if not target_cwe_found:
            print("Warning: No target CWE with score 1.0 found in results.")

        # --- 2. Filter, Sort, and Select Top 3 Related Examples ---
        # Filter for those that have a code example
        related_with_code = [r for r in related_results_pool if r.get('codeExample')]

        # Sort by rank (lower rank is better/higher priority)
        related_with_code.sort(key=lambda x: x.get('rank', float('inf')))

        # Select the top 3
        top_3_related = related_with_code[:3]

        # --- 3. Format the Top 3 Related Examples ---
        if top_3_related:
            # context_parts.append("\nLearn from the fixes demonstrated in the related vulnerability examples within the context to inform your recommended solution for the main vulnerable code.")
            context_parts.append("\nRelated Vulnerability Examples:")
            context_parts.append("=" * 80 + "\n")

            for i, record in enumerate(top_3_related):
                context_parts.append(f"Related Example {i+1} (Rank: {record.get('rank', 'N/A')}, Score: {record.get('score', 'N/A')}, Hops: {record.get('hops', 'N/A')}):")

                # Add CWE Info for the related example
                cwe = record.get('cwe')
                if cwe:
                    context_parts.append("  CWE Information:")
                    context_parts.append(f"    ID: {cwe.get('id', 'N/A')}")
                    context_parts.append(f"    Name: {cwe.get('name', 'N/A')}")
                    context_parts.append(f"    Description: {cwe.get('description', 'N/A')}")

                # Add CVE Info if available
                cve = record.get('cve')
                if cve:
                    context_parts.append("  CVE Information:")
                    context_parts.append(f"    ID: {cve.get('id', 'N/A')}")
                    context_parts.append(f"    Description: {cve.get('description', 'N/A')}")

                # Add Code Example
                code_example = record.get('codeExample')
                if code_example:  # Should be true based on filter, but check anyway
                    context_parts.append("  Code Example:")
                    context_parts.append("    Code Before Fix:")
                    context_parts.append(f"    ```\n{code_example.get('code_before', '# No code provided')}\n    ```")
                    context_parts.append("    Code After Fix:")
                    context_parts.append(f"    ```\n{code_example.get('code_after', '# No code provided')}\n    ```")

                context_parts.append("-" * 80 + "\n")  # Separator for the next example

        # --- 4. Combine all parts into the final context string ---
        return "\n".join(context_parts)


class PagerankGraphHandler(QueryHandler):
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        self.validate_base_params(cwe_id, cve_id)
        
        # Extract optional parameters with defaults
        hops = kwargs.get('hops', 3)
        top_k = kwargs.get('top_k', 5)
        score_prop = kwargs.get('score_prop', 'pr_weighted_shap')
        
        # Query the graph using PageRank approach
        raw_results = self._query_graph(cwe_id, cve_id, hops, top_k, score_prop)
        
        # Format the results
        formatted_results = self._build_context(raw_results)
        
        return {
            "raw_results": raw_results,
            "formatted_results": formatted_results
        }
    
    def _query_graph(self, cwe_id: str, cve_id: str, hops: int, top_k: int, score_prop: str):
        """Execute PageRank-based retrieval for vulnerability examples"""
        graph = get_neo4j_graph().get_graph()
        
        # If specific CVE provided, try to find it first
        if cve_id:
            specific_cve_result = graph.query(
                "MATCH (c:CWE {id:$cid})-[:HAS_VULNERABILITY]->(v:CVE {id:$vid}) RETURN v",
                {"cid": cwe_id, "vid": cve_id}
            )
            if specific_cve_result:
                rank_map = self._get_influential_rank_map(graph, score_prop)
                return [self._query_cwe_details(graph, cwe_id, score_prop, rank_map, override_cve_id=cve_id)]
        
        # Otherwise, get CWE and similar CWEs ordered by PageRank
        return self._query_only_cwe_ordered(graph, cwe_id, hops, top_k, score_prop)
    
    def _get_influential_rank_map(self, graph, score_prop: str):
        """Build a map from CWE id -> global rank based on descending score_prop"""
        query = f"""
        MATCH (n:CWE)
        WHERE n.{score_prop} IS NOT NULL
        RETURN n.id AS id, n.{score_prop} AS score
        ORDER BY score DESC
        """
        result = graph.query(query)
        rank_map = {}
        for i, rec in enumerate(result, start=1):
            rank_map[rec["id"]] = i
        return rank_map
    
    def _query_cwe_details(self, graph, cwe_id: str, score_prop: str, rank_map: dict, override_cve_id: str = None):
        """Query CWE details with CVE and code example"""
        # 1) CWE node with dynamic score_prop
        cwe_result = graph.query(
            f"""
            MATCH (c:CWE {{id:$id}})
            RETURN c {{ .id, .name, .description,
                        .extended_description,
                        .potential_mitigation,
                        .{score_prop} }} AS cwe
            """,
            {"id": cwe_id}
        )
        if not cwe_result:
            return None
        cwe = cwe_result[0]["cwe"]
        influential_rank = rank_map.get(cwe["id"])

        # 2) CVE (override or top by score_prop)
        if override_cve_id:
            cve_query = f"""
            MATCH (c:CWE {{id:$id}})-[:HAS_VULNERABILITY]->(v:CVE {{id:$vid}})
            RETURN v {{ .id, .description, .{score_prop} }} AS cve
            """
            params = {"id": cwe_id, "vid": override_cve_id}
        else:
            cve_query = f"""
            MATCH (c:CWE {{id:$id}})-[:HAS_VULNERABILITY]->(v:CVE)
            RETURN v {{ .id, .description, .{score_prop} }} AS cve
            ORDER BY v.{score_prop} DESC
            LIMIT 1
            """
            params = {"id": cwe_id}

        cve_result = graph.query(cve_query, params)
        if not cve_result:
            return None
        cve = cve_result[0]["cve"]

        # 3) One code example
        ce_result = graph.query(
            f"""
            MATCH (v:CVE {{id:$vid}})-[:HAS_CODE_EXAMPLE]->(ce)
            RETURN ce {{ .id, .code_before, .code_after, .{score_prop} }} AS ce
            ORDER BY ce.id ASC
            LIMIT 1
            """,
            {"vid": cve["id"]}
        )
        if not ce_result:
            return None
        ce = ce_result[0]["ce"]

        return {
            "id": cwe["id"],
            "name": cwe["name"],
            "description": cwe.get("description"),
            "extended_description": cwe.get("extended_description"),
            "potential_mitigation": cwe.get("potential_mitigation"),
            score_prop: cwe[score_prop],
            "influential_rank": influential_rank,
            "related_cve": {
                "id": cve["id"],
                "description": cve.get("description"),
                score_prop: cve[score_prop]
            },
            "code_example": {
                "id": ce["id"],
                score_prop: ce[score_prop],
                "code_before": self._clean_code(ce.get("code_before")),
                "code_after": self._clean_code(ce.get("code_after"))
            },
            "relationship": ["CWE —HAS_VULNERABILITY—> CVE —HAS_CODE_EXAMPLE—> CodeExample"]
        }
    
    def _find_similar_cwes_with_path(self, graph, seed_id: str, hops: int, top_k: int, score_prop: str):
        """Find similar CWEs with path information"""
        rel_types = "HAS_PARENT|PEER_WITH|RELATES_TO"
        
        query = f"""
        MATCH p=(seed:CWE {{id:$id}})-[:{rel_types}*1..{hops}]-(other:CWE)
        WHERE other.id <> $id AND other.{score_prop} IS NOT NULL
        WITH other.id AS cid, other.{score_prop} AS pr, COLLECT(DISTINCT p) AS paths
        ORDER BY pr DESC
        LIMIT $k
        RETURN cid, pr, paths
        """
        
        results = []
        query_result = graph.query(query, {"id": seed_id, "k": top_k})
        
        for rec in query_result:
            cid = rec["cid"]
            path_info = []
            for p in rec["paths"]:
                nodes = [n["id"] for n in p.nodes]
                rels = [r.type for r in p.relationships]
                path_info.append((nodes, rels, rec["pr"]))
            results.append((cid, path_info))
        
        return results
    
    def _build_arrow_strings_for_paths(self, path_info_list):
        """Build arrow notation for relationship paths"""
        arrows = []
        final_cve_code_path = " —HAS_VULNERABILITY—> CVE —HAS_CODE_EXAMPLE—> CodeExample"
        
        for nodes, rels, _ in path_info_list:
            s = nodes[0]
            for i, r in enumerate(rels):
                s += f" —{r}—> {nodes[i+1]}"
            s += final_cve_code_path
            arrows.append(s)
        
        return list(set(arrows))
    
    def _query_only_cwe_ordered(self, graph, seed_cwe_id: str, hops: int, top_k: int, score_prop: str):
        """Query CWE and similar CWEs ordered by PageRank"""
        rank_map = self._get_influential_rank_map(graph, score_prop)
        results = []
        
        # Direct CWE
        base = self._query_cwe_details(graph, seed_cwe_id, score_prop, rank_map)
        if base:
            base["rank"] = 1
            results.append(base)
        
        # Similar CWEs
        rank = 2
        for cid, path_info in self._find_similar_cwes_with_path(graph, seed_cwe_id, hops, top_k, score_prop):
            detail = self._query_cwe_details(graph, cid, score_prop, rank_map)
            if not detail:
                continue
            detail["rank"] = rank
            detail["relationship"] = self._build_arrow_strings_for_paths(path_info)
            results.append(detail)
            rank += 1
        
        return results
    
    def _clean_code(self, code: str) -> str:
        """Clean up code strings for display"""
        import textwrap
        return textwrap.dedent(code or "").strip()
    
    def _build_context(self, results):
        """Build context string for LLM prompt based on PageRank search results"""
        import json
        
        context_parts = []
        
        if not results:
            return "No relevant vulnerability examples found through PageRank traversal."
        
        # Process each result
        for i, result in enumerate(results, 1):
            # Example header with rank and basic info
            rank = result.get('rank', i)
            cwe_id = result.get('id', 'N/A')
            cwe_name = result.get('name', 'N/A')
            
            context_parts.append(f"EXAMPLE {i} (Rank: {rank})")
            context_parts.append("=" * 40)
            context_parts.append("")
            
            # CWE Information
            context_parts.append("CWE INFORMATION:")
            context_parts.append(f"  ID: {cwe_id}")
            context_parts.append(f"  Name: {cwe_name}")
            
            description = result.get('description', 'N/A')
            if description and description != 'N/A':
                wrapped_desc = description[:500] + "..." if len(description) > 500 else description
                context_parts.append(f"  Description: {wrapped_desc}")
            
            extended_desc = result.get('extended_description')
            if extended_desc and extended_desc.strip():
                wrapped_ext_desc = extended_desc[:300] + "..." if len(extended_desc) > 300 else extended_desc
                context_parts.append(f"  Extended Description: {wrapped_ext_desc}")
            
            context_parts.append("")
            
            # CVE Information
            related_cve = result.get('related_cve')
            if related_cve:
                context_parts.append("RELATED CVE INFORMATION:")
                context_parts.append(f"  CVE ID: {related_cve.get('id', 'N/A')}")
                
                cve_description = related_cve.get('description', 'N/A')
                if cve_description and cve_description != 'N/A':
                    wrapped_cve_desc = cve_description[:400] + "..." if len(cve_description) > 400 else cve_description
                    context_parts.append(f"  CVE Description: {wrapped_cve_desc}")
                
                context_parts.append("")
            
            # Code Example
            code_example = result.get('code_example')
            if code_example:
                context_parts.append("CODE EXAMPLE:")
                context_parts.append("")
                
                # Code Before Fix
                code_before = code_example.get('code_before', '# No code provided')
                context_parts.append("  Vulnerable Code (Before Fix):")
                context_parts.append("  ```")
                for line in code_before.split('\n'):
                    context_parts.append(f"  {line}")
                context_parts.append("  ```")
                context_parts.append("")
                
                # Code After Fix
                code_after = code_example.get('code_after', '# No code provided')
                context_parts.append("  Fixed Code (After Fix):")
                context_parts.append("  ```")
                for line in code_after.split('\n'):
                    context_parts.append(f"  {line}")
                context_parts.append("  ```")
                context_parts.append("")
            
            # Relationship Information
            relationships = result.get('relationship', [])
            if relationships:
                context_parts.append("RELATIONSHIP PATH:")
                for rel in relationships:
                    context_parts.append(f"  {rel}")
                context_parts.append("")
            
            # Mitigation Information (if available)
            potential_mitigation = result.get('potential_mitigation')
            if potential_mitigation and potential_mitigation.strip():
                context_parts.append("POTENTIAL MITIGATION STRATEGIES:")
                mitigation_parts = potential_mitigation.split("::")
                for part in mitigation_parts[:3]:  # Show first 3 mitigation strategies
                    if part.strip():
                        clean_part = part.replace("PHASE:", "\n  Phase: ").replace("STRATEGY:", "\n  Strategy: ").replace("DESCRIPTION:", "\n  Description: ")
                        context_parts.append(f"  {clean_part.strip()}")
                context_parts.append("")
            
            # Separator between examples
            if i < len(results):
                context_parts.append("-" * 80)
                context_parts.append("")
        
        # Footer with guidance
        context_parts.append("")
        context_parts.append("GUIDANCE FOR VULNERABILITY REPAIR:")
        context_parts.append("-" * 40)
        context_parts.append("Study the code examples above to understand:")
        context_parts.append("• Common vulnerability patterns and their manifestations")
        context_parts.append("• Specific fixes applied to address similar weaknesses")
        context_parts.append("• Relationship patterns between different vulnerability types")
        context_parts.append("• Mitigation strategies that can be applied")
        context_parts.append("")
        context_parts.append("Use these examples to inform your recommended solution for the target vulnerability.")
        
        return "\n".join(context_parts)


class MetapathGraphHandler(QueryHandler):
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        self.validate_base_params(cwe_id, cve_id)
        
        # Extract optional parameters with defaults
        max_results = kwargs.get('max_results', 10)
        max_per_path = kwargs.get('max_per_path', 3)
        
        # Query the graph using metapath approach
        raw_results = self._query_graph(cwe_id, cve_id, max_results, max_per_path)
        
        # Format the results
        formatted_results = self._build_context(raw_results)
        
        return {
            "raw_results": raw_results,
            "formatted_results": formatted_results
        }
    
    def _query_graph(self, cwe_id: str, cve_id: str, max_results: int, max_per_path: int):
        """Execute meta-path retrieval for vulnerability examples"""
        graph = get_neo4j_graph().get_graph()
        all_results = []
        found_cve_ids = set()
        
        # Path 1: Direct Path (all direct CVEs have weight 1.0)
        try:
            if cve_id:
                # First try to get the specific CVE if provided
                specific_cve_results = graph.query(
                    "MATCH (cwe:CWE {id: $cweId})-[:HAS_VULNERABILITY]->(cve:CVE {id: $cveId})-[:HAS_CODE_EXAMPLE]->(example:CODE_EXAMPLE) RETURN cwe, cve, example LIMIT $limit",
                    {"cveId": cve_id, "cweId": cwe_id, "limit": max_per_path}
                )
                
                for result in specific_cve_results:
                    found_cve_ids.add(result['cve']['id'])
                    all_results.append({
                        'cwe': result['cwe'],
                        'cve': result['cve'],
                        'example': result['example'],
                        'pathType': 'direct',
                        'relationshipType': 'HAS_VULNERABILITY',
                        'pathWeight': 1.0,
                        'pathDescription': 'Direct examples for the queried CWE and specific CVE',
                        'isSpecificCVE': True
                    })
            
            # Then get other direct CVEs (excluding already found ones)
            remaining_limit = max_per_path - len([r for r in all_results if r['pathType'] == 'direct'])
            if remaining_limit > 0:
                exclusion_clause = ""
                params = {"cweId": cwe_id, "limit": remaining_limit}
                
                if found_cve_ids:
                    exclusion_clause = "AND NOT cve.id IN $excludeCves"
                    params["excludeCves"] = list(found_cve_ids)
                
                other_direct_results = graph.query(
                    f"MATCH (cwe:CWE {{id: $cweId}})-[:HAS_VULNERABILITY]->(cve:CVE)-[:HAS_CODE_EXAMPLE]->(example:CODE_EXAMPLE) WHERE true {exclusion_clause} RETURN cwe, cve, example LIMIT $limit",
                    params
                )
                
                for result in other_direct_results:
                    found_cve_ids.add(result['cve']['id'])
                    all_results.append({
                        'cwe': result['cwe'],
                        'cve': result['cve'],
                        'example': result['example'],
                        'pathType': 'direct',
                        'relationshipType': 'HAS_VULNERABILITY',
                        'pathWeight': 0.9,
                        'pathDescription': 'Direct examples for the queried CWE (but different CVEs)',
                        'isSpecificCVE': False
                    })
        except Exception as e:
            print(f"Direct path query failed: {e}")
        
        # Only proceed to other paths if we don't have enough results yet
        current_count = len(all_results)
        if current_count < max_results:
            remaining_needed = max_results - current_count
            
            # Path 2: Peer Path (weight 0.8)
            try:
                exclusion_clause = ""
                params = {"cweId": cwe_id, "limit": min(max_per_path, remaining_needed)}
                
                if found_cve_ids:
                    exclusion_clause = "AND NOT cve.id IN $excludeCves"
                    params["excludeCves"] = list(found_cve_ids)
                
                peer_results = graph.query(
                    f"MATCH (cwe:CWE {{id: $cweId}})-[:PEER_WITH]->(peer:CWE)-[:HAS_VULNERABILITY]->(cve:CVE)-[:HAS_CODE_EXAMPLE]->(example:CODE_EXAMPLE) WHERE true {exclusion_clause} RETURN peer AS cwe, cve, example LIMIT $limit",
                    params
                )
                
                for result in peer_results:
                    found_cve_ids.add(result['cve']['id'])
                    all_results.append({
                        'cwe': result['cwe'],
                        'cve': result['cve'],
                        'example': result['example'],
                        'pathType': 'peer',
                        'relationshipType': 'PEER_WITH',
                        'pathWeight': 0.8,
                        'pathDescription': 'Examples from peer CWEs at same level',
                        'isSpecificCVE': False
                    })
            except Exception as e:
                print(f"Peer path query failed: {e}")
        
        # Update remaining count
        current_count = len(all_results)
        if current_count < max_results:
            remaining_needed = max_results - current_count
            
            # Path 3: Parent Path (weight 0.6)
            try:
                exclusion_clause = ""
                params = {"cweId": cwe_id, "limit": min(max_per_path, remaining_needed)}
                
                if found_cve_ids:
                    exclusion_clause = "AND NOT cve.id IN $excludeCves"
                    params["excludeCves"] = list(found_cve_ids)
                
                parent_results = graph.query(
                    f"MATCH (cwe:CWE {{id: $cweId}})-[:HAS_PARENT]->(parent:CWE)-[:HAS_VULNERABILITY]->(cve:CVE)-[:HAS_CODE_EXAMPLE]->(example:CODE_EXAMPLE) WHERE true {exclusion_clause} RETURN parent AS cwe, cve, example LIMIT $limit",
                    params
                )
                
                for result in parent_results:
                    found_cve_ids.add(result['cve']['id'])
                    all_results.append({
                        'cwe': result['cwe'],
                        'cve': result['cve'],
                        'example': result['example'],
                        'pathType': 'parent',
                        'relationshipType': 'HAS_PARENT',
                        'pathWeight': 0.6,
                        'pathDescription': 'Examples from parent CWE category',
                        'isSpecificCVE': False
                    })
            except Exception as e:
                print(f"Parent path query failed: {e}")
        
        # Update remaining count
        current_count = len(all_results)
        if current_count < max_results:
            remaining_needed = max_results - current_count
            
            # Path 4: Related Path (weight 0.4)
            try:
                exclusion_clause = ""
                params = {"cweId": cwe_id, "limit": min(max_per_path, remaining_needed)}
                
                if found_cve_ids:
                    exclusion_clause = "AND NOT cve.id IN $excludeCves"
                    params["excludeCves"] = list(found_cve_ids)
                
                related_results = graph.query(
                    f"MATCH (cwe:CWE {{id: $cweId}})-[:RELATES_TO]->(related:CWE)-[:HAS_VULNERABILITY]->(cve:CVE)-[:HAS_CODE_EXAMPLE]->(example:CODE_EXAMPLE) WHERE true {exclusion_clause} RETURN related AS cwe, cve, example LIMIT $limit",
                    params
                )
                
                for result in related_results:
                    found_cve_ids.add(result['cve']['id'])
                    all_results.append({
                        'cwe': result['cwe'],
                        'cve': result['cve'],
                        'example': result['example'],
                        'pathType': 'related',
                        'relationshipType': 'RELATES_TO',
                        'pathWeight': 0.4,
                        'pathDescription': 'Examples from generally related CWEs',
                        'isSpecificCVE': False
                    })
            except Exception as e:
                print(f"Related path query failed: {e}")
        
        # Sort by path weight (highest first)
        sorted_results = sorted(
            all_results,
            key=lambda x: (-x['pathWeight'], x['cve']['id'])
        )
        
        # Limit to max_results and add ranking
        final_results = []
        for i, result in enumerate(sorted_results[:max_results]):
            final_results.append({
                'result': {
                    'rank': i + 1,
                    'score': result['pathWeight'],
                    'cwe': dict(result['cwe']),
                    'cve': dict(result['cve']),
                    'codeExample': dict(result['example']),
                    'pathType': result['pathType'],
                    'relationshipType': result['relationshipType'],
                    'pathDescription': result['pathDescription']
                }
            })
        
        return final_results
    
    def _build_context(self, results):
        """Build context string for LLM prompt based on meta-path search results"""
        context_parts = []
        
        if not results:
            return "No relevant vulnerability examples found through meta-path traversal."
        
        # Group results by path type for better organization
        path_groups = {}
        for item in results:
            record = item.get('result', {})
            path_type = record.get('pathType', 'unknown')
            
            if path_type not in path_groups:
                path_groups[path_type] = []
            path_groups[path_type].append(record)
        
        # Order path types by semantic relevance
        path_order = ['direct', 'parent', 'peer', 'related']
        
        context_parts.append("")  # Empty line for spacing
        
        example_count = 0
        
        for path_type in path_order:
            if path_type in path_groups and example_count < 5:  # Limit to top 5 overall
                path_results = path_groups[path_type]
                
                # Path type header
                context_parts.append(f"{path_type.upper()} PATH EXAMPLES:")
                context_parts.append(f"({path_results[0].get('pathDescription', '')})")
                context_parts.append("-" * 40)
                context_parts.append("")  # Empty line
                
                for record in path_results[:2]:  # Max 2 per path type
                    if example_count >= 5:
                        break
                        
                    example_count += 1
                    
                    # Example header
                    rank = record.get('rank', 'N/A')
                    score = record.get('score', 'N/A')
                    relationship = record.get('relationshipType', 'N/A')
                    
                    context_parts.append(f"Example {example_count}")
                    context_parts.append(f"  Rank: {rank}")
                    context_parts.append(f"  Score: {score}")
                    context_parts.append(f"  Relationship: {relationship}")
                    context_parts.append("")  # Empty line

                    # Add CWE Info
                    cwe = record.get('cwe')
                    if cwe:
                        context_parts.append("  CWE Information:")
                        context_parts.append(f"    ID: {cwe.get('id', 'N/A')}")
                        context_parts.append(f"    Name: {cwe.get('name', 'N/A')}")
                        context_parts.append(f"    Description: {cwe.get('description', 'N/A')}")
                        context_parts.append("")  # Empty line

                    # Add CVE Info
                    cve = record.get('cve')
                    if cve:
                        context_parts.append("  CVE Information:")
                        context_parts.append(f"    ID: {cve.get('id', 'N/A')}")
                        context_parts.append(f"    Description: {cve.get('description', 'N/A')}")
                        context_parts.append("")  # Empty line

                    # Add Code Example
                    code_example = record.get('codeExample')
                    if code_example:
                        context_parts.append("  Code Example:")
                        context_parts.append("")  # Empty line before code
                        
                        context_parts.append("    Code Before Fix:")
                        code_before = code_example.get('code_before', '# No code provided')
                        context_parts.append(f"    ```")
                        context_parts.append(f"{code_before}")
                        context_parts.append(f"    ```")
                        context_parts.append("")  # Empty line between code blocks
                        
                        context_parts.append("    Code After Fix:")
                        code_after = code_example.get('code_after', '# No code provided')
                        context_parts.append(f"    ```")
                        context_parts.append(f"{code_after}")
                        context_parts.append(f"    ```")
                        context_parts.append("")  # Empty line after code

                    context_parts.append("-" * 40)
                    context_parts.append("")  # Empty line after separator
        
        # Footer
        context_parts.append("")  # Extra spacing before footer
        context_parts.append("Learn from the fixes demonstrated in these meta-path retrieved examples to inform your recommended solution.")
        
        return "\n".join(context_parts)