"""
Evaluation logic using deepeval for code repair assessment.
"""

from deepeval.metrics import GEval
from deepeval.test_case import LLMTestCaseParams, LLMTestCase
from typing import Dict
from app.core.storage import criteria_storage

def get_criteria_as_rubrics() -> list:
    """Get criteria from storage and format as evaluation rubrics"""
    criteria_list = criteria_storage.find_many({})
    rubrics = []
    
    for criteria in criteria_list:
        rubric = {
            "name": criteria["name"],
            "criteria": criteria["criteria"],
            "evaluation_steps": criteria["evaluation_steps"]
        }
        rubrics.append(rubric)
    
    return rubrics


def create_input_text(cwe: str, cve: str, code_snippet: str) -> str:
    """Create input text for evaluation"""
    return f"""
        ### CVE-ID
        {cve}

        ### CWE-ID
        {cwe}
    
        ### Vulnerable Code and Fix
        {code_snippet}
    """


def evaluate_recommendation(
    vulnerable_code: str,
    cwe_id: str,
    cve_id: str,
    recommendation: str,
    retrieved_context: str,
    model: str = "gpt-4o"
) -> Dict[str, float]:
    """
    Evaluate a code repair recommendation using deepeval.
    
    Args:
        vulnerable_code: The vulnerable code
        cwe_id: The CWE identifier
        cve_id: The CVE identifier
        recommendation: The recommendation to evaluate
        retrieved_context: The context retrieved from pattern matching
        model: The model to use for evaluation
        
    Returns:
        Dictionary containing scores for each criterion
    """
    code_snippet = f"""
    Code Before Fix:
    {vulnerable_code}
    """
    
    # Create input text
    input_text = create_input_text(cwe_id, cve_id, code_snippet)
    
    # Store results
    scores = {}
    
    # Get criteria from storage and evaluate against each rubric
    rubrics = get_criteria_as_rubrics()
    for rubric in rubrics:
        g_eval = GEval(
            **rubric,
            model=model,
            evaluation_params=[LLMTestCaseParams.INPUT, LLMTestCaseParams.ACTUAL_OUTPUT, LLMTestCaseParams.CONTEXT]
        )
        
        test_case = LLMTestCase(
            input=input_text,
            actual_output=recommendation,
            context=[retrieved_context]
        )
        
        # Measure the test case
        g_eval.measure(test_case)
        
        # Store the score
        scores[f"{rubric['name']} Score"] = float(g_eval.score)
    
    return scores