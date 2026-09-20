import os
from langchain_deepseek import ChatDeepSeek
from dotenv import load_dotenv

load_dotenv()

def get_llm():
    """
    Returns the configured DeepSeek instance.
    """
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        print("Warning: DEEPSEEK_API_KEY not found in environment variables.")
        # We allow it to fail later if the key is missing, or user can input it.

    return ChatDeepSeek(
        model=os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
        api_key=api_key,
        temperature=0
    )
