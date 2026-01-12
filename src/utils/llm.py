import os
from langchain_gigachat import GigaChat
from dotenv import load_dotenv

load_dotenv()

def get_llm():
    """
    Returns the configured GigaChat instance.
    """
    credentials = os.getenv("GIGACHAT_CREDENTIALS")
    if not credentials:
        print("Warning: GIGACHAT_CREDENTIALS not found in environment variables.")
        # We allow it to fail later if the key is missing, or user can input it.
    
    return GigaChat(
        credentials=credentials,
        verify_ssl_certs=False,
        temperature=0
    )
