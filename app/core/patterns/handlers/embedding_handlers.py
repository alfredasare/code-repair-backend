import json
from typing import Any, Dict
import torch
from pinecone import Pinecone
from sentence_transformers import SentenceTransformer
from transformers import AutoModelForMaskedLM, AutoTokenizer
from app.core.config import settings
from ..base import QueryHandler


class VanillaEmbeddingHandler(QueryHandler):
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        self.validate_base_params(cwe_id, cve_id)
        # TODO: Implement vanilla embedding query logic
        return {
            "raw_results": {},
            "formatted_results": "VanillaEmbeddingHandler not yet implemented"
        }


class MetadataEmbeddingHandler(QueryHandler):
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        self.validate_base_params(cwe_id, cve_id)
        # TODO: Implement metadata embedding query logic
        return {
            "raw_results": {},
            "formatted_results": "MetadataEmbeddingHandler not yet implemented"
        }


class SegCtxEmbeddingHandler(QueryHandler):
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        self.validate_base_params(cwe_id, cve_id)
        # TODO: Implement segment context embedding query logic
        return {
            "raw_results": {},
            "formatted_results": "SegCtxEmbeddingHandler not yet implemented"
        }


class MetadrivenEmbeddingHandler(QueryHandler):
    def execute_query(self, cwe_id: str, cve_id: str, **kwargs) -> Dict[str, Any]:
        self.validate_base_params(cwe_id, cve_id)
        
        # Initialize Pinecone client
        pc = Pinecone(api_key=settings.pinecone_api_key)
        
        # Initialize indices
        mitre_index_name = 'metadata-aug-mitre'
        bigvul_index_name = 'metadata-retrieval-bigvul'
        cvefixes_index_name = 'code-fixing-metadata-aug'
        
        mitre_index = pc.Index(mitre_index_name)
        bigvul_index = pc.Index(bigvul_index_name)
        cvefixes_index = pc.Index(cvefixes_index_name)
        
        # Initialize models
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
        
        try:
            dense_model = SentenceTransformer(
                'msmarco-bert-base-dot-v5',
                device=device
            )
            
            model_id = 'naver/splade-cocondenser-ensembledistil'
            tokenizer = AutoTokenizer.from_pretrained(model_id)
            sparse_model = AutoModelForMaskedLM.from_pretrained(model_id)
            
            # Create query and encode
            query = f"cwe_id: {cwe_id}"
            dense_vec, sparse_vec = self._encode(query, dense_model, tokenizer, sparse_model, device)
        except Exception as e:
            return {
                "raw_results": {},
                "formatted_results": f"Model initialization failed: {str(e)}"
            }

        
        top_k = kwargs.get('top_k', 3)
        
        # Query all three indices
        cvefixes_results = cvefixes_index.query(
            vector=dense_vec, 
            sparse_vector=sparse_vec, 
            top_k=top_k,
            filter={
                "cwe": {"$eq": cwe_id},
                "cve": {"$eq": cve_id}
            },
            include_metadata=True
        )
        
        bigvul_results = bigvul_index.query(
            vector=dense_vec, 
            sparse_vector=sparse_vec, 
            top_k=top_k,
            filter={
                "cwe": {"$eq": cwe_id},
                "cve": {"$eq": cve_id}
            },
            include_metadata=True
        )
        
        mitre_results = mitre_index.query(
            vector=dense_vec, 
            sparse_vector=sparse_vec, 
            top_k=top_k,
            filter={
                "cwe": {"$eq": cwe_id},
            },
            include_metadata=True
        )
        
        # Build context using the existing function
        formatted_results = self._build_context(mitre_results, bigvul_results, cvefixes_results)
        
        return {
            "raw_results": {
                "mitre": json.loads(json.dumps(mitre_results, default=str)) if mitre_results else {},
                "bigvul": json.loads(json.dumps(bigvul_results, default=str)) if bigvul_results else {},
                "cvefixes": json.loads(json.dumps(cvefixes_results, default=str)) if cvefixes_results else {}
            },
            "formatted_results": formatted_results
        }
    
    def _encode(self, text: str, dense_model, tokenizer, sparse_model, device):
        """Encode text into dense and sparse vectors"""
        try:
            # Create dense vec
            dense_vec = dense_model.encode(text).tolist()
            
            # Create sparse vec
            input_ids = tokenizer(text, return_tensors='pt')
            with torch.no_grad():
                outputs = sparse_model(**input_ids.to(device))
                sparse_vec = torch.log(1 + torch.relu(outputs.logits)) * input_ids.attention_mask.unsqueeze(-1)
                sparse_vec = torch.max(sparse_vec, dim=1)[0].squeeze()
            
            # Convert to dictionary format
            indices = sparse_vec.nonzero().squeeze().cpu().tolist()
            values = sparse_vec[indices].cpu().tolist()
            sparse_dict = {"indices": indices, "values": values}
            
            return dense_vec, sparse_dict
        except Exception as e:
            raise Exception(f"Encoding failed: {str(e)}")
    
    def _build_context(self, mitre_results, bigvul_results, cvefixes_results):
        """Build context string for LLM prompt based on Pinecone search results"""
        context_parts = []
        
        # --- 1. MITRE CWE Information (Primary Knowledge Base) ---
        if mitre_results and mitre_results.get('matches'):
            mitre_match = mitre_results['matches'][0]  # Take the top match
            metadata = mitre_match.get('metadata', {})
            
            context_parts.append("TARGET CWE INFORMATION:")
            context_parts.append("=" * 80)
            context_parts.append("")
            
            # CWE Details
            cwe_id = metadata.get('cwe', 'N/A')
            cwe_description = metadata.get('cwe_description', 'N/A')
            extended_description = metadata.get('extended_cwe_description', '')
            potential_mitigations = metadata.get('potential_mitigations', '')
            
            context_parts.append(f"CWE ID: {cwe_id}")
            context_parts.append(f"Description: {cwe_description}")
            context_parts.append("")
            
            if extended_description and extended_description.strip():
                # Truncate if too long for readability
                extended_desc = extended_description[:1000] + "..." if len(extended_description) > 1000 else extended_description
                context_parts.append("Extended Description:")
                context_parts.append(extended_desc.strip())
                context_parts.append("")
            
            if potential_mitigations and potential_mitigations.strip():
                context_parts.append("Potential Mitigations:")
                # Parse mitigation strategies if they follow a structured format
                mitigation_parts = potential_mitigations.split("::")
                for part in mitigation_parts[:3]:  # Show first 3 mitigation strategies
                    if part.strip():
                        clean_part = part.replace("PHASE:", "\n  Phase: ").replace("STRATEGY:", "\n  Strategy: ").replace("DESCRIPTION:", "\n  Description: ")
                        context_parts.append(f"  {clean_part.strip()}")
                context_parts.append("")
            
            context_parts.append("-" * 80)
            context_parts.append("")
        
        # --- 2. CVEFixes Examples (Process ALL results to aggregate fragmented data) ---
        if cvefixes_results and cvefixes_results.get('matches'):
            context_parts.append("CVEFIXES CODE EXAMPLES:")
            context_parts.append("=" * 80)
            context_parts.append("")
            
            # Group results by CVE ID to aggregate fragmented data
            cve_data = {}
            
            for match in cvefixes_results['matches']:
                metadata = match.get('metadata', {})
                cve_id = metadata.get('cve', 'Unknown')
                
                if cve_id not in cve_data:
                    cve_data[cve_id] = {
                        'cve_id': cve_id,
                        'cwe_id': metadata.get('cwe', 'N/A'),
                        'cwe_name': metadata.get('cwe_name', 'N/A'),
                        'cve_description': metadata.get('cve_description', ''),
                        'cwe_description': metadata.get('cwe_description', ''),
                        'extended_cwe_description': metadata.get('extended_cwe_description', ''),
                        'func_before': metadata.get('func_before', ''),
                        'func_after': metadata.get('func_after', ''),
                        'score': match.get('score', 0)
                    }
                else:
                    # Merge data - prefer non-empty values
                    existing = cve_data[cve_id]
                    existing['cve_description'] = existing['cve_description'] or metadata.get('cve_description', '')
                    existing['cwe_description'] = existing['cwe_description'] or metadata.get('cwe_description', '')
                    existing['extended_cwe_description'] = existing['extended_cwe_description'] or metadata.get('extended_cwe_description', '')
                    existing['func_before'] = existing['func_before'] or metadata.get('func_before', '')
                    existing['func_after'] = existing['func_after'] or metadata.get('func_after', '')
                    existing['cwe_name'] = existing['cwe_name'] if existing['cwe_name'] != 'N/A' else metadata.get('cwe_name', 'N/A')
                    # Keep highest score
                    existing['score'] = max(existing['score'], match.get('score', 0))
            
            # Sort by score and take top results
            sorted_cves = sorted(cve_data.values(), key=lambda x: x['score'], reverse=True)
            
            example_count = 0
            for cve_info in sorted_cves[:3]:  # Max 3 CVE examples
                example_count += 1
                
                context_parts.append(f"CVEFixes Example {example_count}:")
                context_parts.append("")
                
                # CVE and CWE information
                context_parts.append(f"  CVE ID: {cve_info['cve_id']}")
                context_parts.append(f"  CWE ID: {cve_info['cwe_id']}")
                if cve_info['cwe_name'] != 'N/A':
                    context_parts.append(f"  CWE Name: {cve_info['cwe_name']}")
                
                if cve_info['cve_description']:
                    # Truncate description for readability
                    desc = cve_info['cve_description'][:400] + "..." if len(cve_info['cve_description']) > 400 else cve_info['cve_description']
                    context_parts.append(f"  CVE Description: {desc}")
                
                if cve_info['cwe_description']:
                    # Add CWE description if available and different from MITRE
                    desc = cve_info['cwe_description'][:300] + "..." if len(cve_info['cwe_description']) > 300 else cve_info['cwe_description']
                    context_parts.append(f"  CWE Description: {desc}")
                
                context_parts.append("")
                
                # Code examples (if available)
                if cve_info['func_before'] and cve_info['func_after']:
                    context_parts.append("  Code Before Fix (Vulnerable):")
                    context_parts.append("  ```")
                    for line in cve_info['func_before'].split('\n'):
                        context_parts.append(f"  {line}")
                    context_parts.append("  ```")
                    context_parts.append("")
                    
                    context_parts.append("  Code After Fix (Secure):")
                    context_parts.append("  ```")
                    for line in cve_info['func_after'].split('\n'):
                        context_parts.append(f"  {line}")
                    context_parts.append("  ```")
                    context_parts.append("")
                else:
                    context_parts.append("  [No code example available for this CVE]")
                    context_parts.append("")
                
                if example_count < len(sorted_cves) and example_count < 3:
                    context_parts.append("-" * 40)
                    context_parts.append("")
            
            context_parts.append("-" * 80)
            context_parts.append("")
        
        # --- 3. BigVul Examples (Show ALL results, even if code is identical) ---
        if bigvul_results and bigvul_results.get('matches'):
            context_parts.append("BIGVUL CODE EXAMPLES:")
            context_parts.append("=" * 80)
            context_parts.append("")
            
            for i, match in enumerate(bigvul_results['matches'][:2]):  # Max 2 examples
                metadata = match.get('metadata', {})
                
                context_parts.append(f"BigVul Example {i+1}:")
                context_parts.append("")
                
                # CVE and vulnerability information
                cve_id = metadata.get('cve', 'N/A')
                cwe_id = metadata.get('cwe', 'N/A')
                summary = metadata.get('Summary', '')
                
                context_parts.append(f"  CVE ID: {cve_id}")
                context_parts.append(f"  CWE ID: {cwe_id}")
                
                if summary:
                    # Truncate summary for readability
                    summ = summary[:300] + "..." if len(summary) > 300 else summary
                    context_parts.append(f"  Summary: {summ}")
                
                context_parts.append("")
                
                # Code examples (show even if identical)
                func_before = metadata.get('func_before', '')
                func_after = metadata.get('func_after', '')
                
                if func_before and func_after:
                    context_parts.append("  Code Before Fix (Vulnerable):")
                    context_parts.append("  ```")
                    for line in func_before.split('\n'):
                        context_parts.append(f"  {line}")
                    context_parts.append("  ```")
                    context_parts.append("")
                    
                    context_parts.append("  Code After Fix (Secure):")
                    context_parts.append("  ```")
                    for line in func_after.split('\n'):
                        context_parts.append(f"  {line}")
                    context_parts.append("  ```")
                    context_parts.append("")
                else:
                    context_parts.append("  [No code example available]")
                    context_parts.append("")
                
                if i < len(bigvul_results['matches']) - 1:
                    context_parts.append("-" * 40)
                    context_parts.append("")
            
            context_parts.append("-" * 80)
            context_parts.append("")
        
        # --- 4. Guidance Footer ---
        context_parts.append("GUIDANCE FOR VULNERABILITY REPAIR:")
        context_parts.append("-" * 40)
        context_parts.append("Study the code examples above to understand:")
        context_parts.append("• Common vulnerability patterns and their manifestations")
        context_parts.append("• Specific fixes applied to address similar weaknesses")
        context_parts.append("• Security best practices demonstrated in the fixed code")
        context_parts.append("• How to properly validate, sanitize, or restructure vulnerable code")
        context_parts.append("")
        context_parts.append("Use these examples to inform your recommended solution for the target vulnerability.")
        
        # Return empty message if no useful results found
        if len(context_parts) <= 10:  # Just headers and guidance
            return "No relevant vulnerability examples found in the knowledge base."
        
        return "\n".join(context_parts)