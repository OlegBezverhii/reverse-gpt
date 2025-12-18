from langchain_core.messages import SystemMessage, HumanMessage
from src.state import ReverseEngineeringState
from src.utils.llm import get_llm

def normalize_code_node(state: ReverseEngineeringState) -> dict:
    """
    Node that normalizes the decompiled code to make it more readable.
    It renames variables and adds comments.
    """
    raw_code = state.get("decompiled_code")
    if not raw_code:
        return {"normalized_code": "No code available to normalize."}
    
    # Check if the decompiled code is actually an error message
    error_indicators = [
        "No function found at",
        "Decompilation failed",
        "Could you please share the raw decompiled C code",
        "It looks like the decompiler didn't locate a function"
    ]
    
    if any(indicator in raw_code for indicator in error_indicators):
        return {"normalized_code": f"Decompilation error: {raw_code}"}

    llm = get_llm()
    
    prompt = """You are an expert reverse engineer. 
    Your task is to take the following raw decompiled C code (likely from Ghidra) and 'normalize' it.
    1. Rename generic variables (e.g., iVar1, uVar2) to meaningful names based on context if possible.
    2. Add comments explaining the logic.
    3. Do NOT change the logic.
    
    Return ONLY the normalized code.
    """
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content=raw_code)
    ]
    
    response = llm.invoke(messages)
    
    return {"normalized_code": response.content}
