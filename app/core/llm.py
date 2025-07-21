from typing import Optional
from langchain_openai import ChatOpenAI
from langchain_groq import ChatGroq
from app.core.config import settings
from app.core.storage import model_storage

class LLMFactory:
    @staticmethod
    def create_llm(
        model_type: str = "openai",
        model_id: str = "gpt-4o-mini",
        temperature: float = 0,
        max_tokens: Optional[int] = None,
        timeout: Optional[int] = None,
        max_retries: int = 2
    ):
        if model_type == "openai":
            return ChatOpenAI(
                model=model_id,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
                max_retries=max_retries,
                api_key=settings.openai_api_key
            )
        elif model_type == "groq":
            model = model_storage.find_by_model_id(model_id)
            reasoning = model.get("reasoning", False)
    
            reasoning_format = "hidden" if reasoning else None
            return ChatGroq(
                model=model_id,
                temperature=temperature,
                max_tokens=max_tokens,
                reasoning_format=reasoning_format,
                timeout=timeout,
                max_retries=max_retries,
                api_key=settings.groq_api_key
            )
        else:
            raise ValueError(f"Unsupported model type: {model_type}")