from langchain_core.messages import SystemMessage, HumanMessage
from src.state import ReverseEngineeringState
from src.utils.llm import get_llm

def normalize_code_node(state: ReverseEngineeringState) -> dict:
    raw_code = state.get("decompiled_code")
    if not raw_code:
        return {"normalized_code": "No code available to normalize."}
    
    error_indicators = [
        "No function found at",
        "Decompilation failed",
        "Could you please share the raw decompiled C code",
        "It looks like the decompiler didn't locate a function"
    ]
    
    if any(indicator in raw_code for indicator in error_indicators):
        return {"normalized_code": f"Decompilation error: {raw_code}"}

    llm = get_llm()
    
    prompt = """Ты — эксперт по реверс-инжинирингу.
    Твоя задача — взять предоставленный сырой декомпилированный C-код (из Ghidra) и "нормализовать" его для удобства чтения.
    
    ИНСТРУКЦИИ:
    1. Переименуй неинформативные переменные (типа iVar1, uVar2, param_1) в осмысленные имена на английском языке, основываясь на контексте их использования.
    2. Добавь комментарии НА РУССКОМ ЯЗЫКЕ, объясняющие, что делает каждая ключевая строка или блок кода.
    3. Сохрани оригинальную логику программы неизменной.
    4. Если код содержит строки или вызовы API, используй их для понимания смысла переменных.
    
    Верни ТОЛЬКО нормализованный код (блок кода).
    """
    
    messages = [
        SystemMessage(content=prompt),
        HumanMessage(content=raw_code)
    ]
    
    response = llm.invoke(messages)
    
    return {"normalized_code": response.content}