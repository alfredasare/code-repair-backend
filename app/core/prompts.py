from langchain.prompts import ChatPromptTemplate

# ─── CODE REPAIR RECOMMENDATION PROMPTS ─────────────────────────────────────────

REPAIR_RECOMMENDATION_MESSAGES = [
    ("system", "You are a software engineer and software vulnerability expert who specializes in recommending fixes for vulnerable code affected by different CWEs and CVEs."),
    ("human", """
        # CONTEXT #
        You are a software engineer and software vulnerability expert who specializes in recommending fixes for vulnerable code affected by different CWEs and CVEs. This includes understanding the specific vulnerabilities and their potential impacts.
    
        # OBJECTIVE #
        Your task is to recommend fixes for the provided vulnerable code. The recommendations should address the specific CWE in question and ensure that the code is secure against the identified vulnerabilities.
    
        # STYLE #
        Write in a technical and concise manner, providing clear and actionable steps. 
    
        # TONE #
        Professional and technical.
    
        # AUDIENCE #
        The target audience is software developers and security professionals who are looking to secure their code against known vulnerabilities.
    
        # RESPONSE FORMAT #
        Provide a structured recommendation in the following format:
        - Issue: [Brief description of the vulnerability]
        - Recommendation: [Detailed steps to fix the vulnerability]
        - Fix: [Code snippet demonstrating the fix]
        
    
        For the following vulnerable code, using this context that contains extra information and previous vulnerable code examples and fixes for the CWE in question, recommend how the vulnerable code can be fixed:
     
        Vulnerable Information:
        CWE: {cwe_id}
        CVE: {cve_id}
     
        Vulnerable Code:
        {vulnerable_code}
    
        Context:
        {retrieved_context}
    """),
]

CODE_REPAIR_RECOMMENDATION_PROMPT = ChatPromptTemplate.from_messages(REPAIR_RECOMMENDATION_MESSAGES)

# ─── CODE FIX GENERATION PROMPTS ────────────────────────────────────────────────

FIX_GENERATION_MESSAGES = [
    ("system", "You are a software engineer and security expert who specializes in generating fixes for vulnerable code affected by different CWEs and CVEs."),
    ("human", """
        # CONTEXT #
        You are a software engineer and security expert who specializes in generating fixes for vulnerable code affected by different CWEs and CVEs.
        
        # OBJECTIVE #
        Generate a fix for the given vulnerable code based on the provided context.
        
        # STYLE #
        Provide the fixed code snippet only, following best practices for secure and efficient coding.
        
        # TONE #
        Professional and technical.
        
        # AUDIENCE #
        Software engineers and security experts.
        
        # RESPONSE FORMAT #
        The response should be a single corrected code snippet without any additional explanations or comments.
        
        # PROMPT #
        Based on the following vulnerable code and the given recommendation, generate a fixed version of the code:
        
        Vulnerable Information:
        CWE: {cwe_id}
        CVE: {cve_id}
     
        Vulnerable Code:
        {vulnerable_code}
    
        Recommendation:
        {recommendation}
    """),
]

CODE_FIX_GENERATION_PROMPT = ChatPromptTemplate.from_messages(FIX_GENERATION_MESSAGES)

# ─── HELPER FUNCTIONS ───────────────────────────────────────────────────────────

def get_repair_recommendation_prompt(pattern_id: str, context: str, vulnerable_code: str) -> str:
    """
    Get the complete prompt for code repair recommendation generation.
    
    Args:
        pattern_id: The pattern used for context retrieval
        context: The retrieved context from the pattern
        vulnerable_code: The vulnerable code to analyze
        
    Returns:
        Complete formatted prompt for LLM
    """
    return CODE_REPAIR_RECOMMENDATION_PROMPT.invoke({
        "cwe_id": pattern_id,
        "cve_id": pattern_id,
        "vulnerable_code": vulnerable_code,
        "retrieved_context": context
    })


def get_code_fix_prompt(cwe_id: str, cve_id: str, vulnerable_code: str, recommendation: str):
    """
    Get the complete prompt for code fix generation.
    
    Args:
        cwe_id: The CWE identifier
        cve_id: The CVE identifier
        vulnerable_code: The original vulnerable code
        recommendation: The repair recommendation
        
    Returns:
        Complete formatted prompt for LLM
    """
    return CODE_FIX_GENERATION_PROMPT.invoke({
        "cwe_id": cwe_id,
        "cve_id": cve_id,
        "vulnerable_code": vulnerable_code,
        "recommendation": recommendation
    })