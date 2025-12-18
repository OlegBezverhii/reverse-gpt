import re
from typing import Annotated, Literal
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage
from src.state import ReverseEngineeringState
from src.utils.llm import get_llm
from src.tools.ghidra import analyze_binary_structure as _analyze_binary_structure
from src.tools.ghidra_wrappers import (
    get_decompiled_code_at_address, 
    list_functions, 
    analyze_binary_structure,
    read_memory_bytes,
    set_binary_path
)
from src.tools.python_tool import run_python_code

# --- Node Definitions ---

def analyze_node(state: ReverseEngineeringState):
    """Performs initial binary analysis."""
    print("--- Step 1: Analyzing Binary ---")
    path = state["binary_path"]
    set_binary_path(path)
    analysis = _analyze_binary_structure.invoke({"file_path": path})
    return {"analysis_report": analysis}

def fetch_code_node(state: ReverseEngineeringState):
    """Fetches the initial decompiled code (e.g., from entry point)."""
    print("--- Step 2: Fetching Decompiled Code ---")
    path = state["binary_path"]
    # Extract entry point from analysis or use default
    entry = state.get("current_function_address")
    
    if not entry:
        # Try to parse entry from analysis report
        report = state.get("analysis_report", "")
        match = re.search(r"Entry Point: \s*([0-9a-fA-Fx]+)", report, re.IGNORECASE)
        if match:
            entry = match.group(1)
        else:
            entry = "0x401050" # Fallback default
            
    print(f"DEBUG: Using entry point: {entry}")
    code = get_decompiled_code_at_address.invoke({"address": entry, "file_path": path})
    
    # If no function found at entry point, try to find any function
    if "No function found at" in code:
        print(f"DEBUG: No function at {entry}, getting list of available functions...")
        functions_list = list_functions.invoke({"file_path": path})
        print(f"DEBUG: Available functions: {functions_list}")
        
        # Try to extract first function address from the list
        func_match = re.search(r"(0x[0-9a-fA-F]+):", functions_list)
        if func_match:
            first_func_addr = func_match.group(1)
            print(f"DEBUG: Trying first available function at {first_func_addr}")
            code = get_decompiled_code_at_address.invoke({"address": first_func_addr, "file_path": path})
        else:
            code = f"Could not find any functions in the binary. Available functions:\n{functions_list}"
    
    return {"decompiled_code": code}

def report_node(state: ReverseEngineeringState):
    """Generates the initial report."""
    print("--- Step 3: Generating Report ---")
    analysis = state["analysis_report"]
    
    report = f"""# Анализ бинарного файла

{analysis}

Файл готов к анализу. Задавайте вопросы о функциях, коде или структуре бинарного файла."""
    
    return {"messages": [AIMessage(content=report)], "is_report_generated": True}

def chatbot_node(state: ReverseEngineeringState):
    """
    Handles user interaction after the report is generated.
    It can decide to call tools or answer directly.
    """
    # Ensure binary path is set for tools
    set_binary_path(state['binary_path'])
    
    llm = get_llm()
    tools = [get_decompiled_code_at_address, analyze_binary_structure, list_functions, run_python_code, read_memory_bytes]
    
    # Check tool call count to prevent infinite loops
    tool_call_count = state.get("tool_call_count", 0)
    MAX_TOOL_CALLS = 30
    
    if tool_call_count >= MAX_TOOL_CALLS:
        # Force final answer without tools
        llm_to_use = llm
        system_msg = """Отвечай на русском языке. 
Ты достиг лимита вызовов инструментов. Дай ФИНАЛЬНЫЙ ответ на основе имеющейся информации."""
    else:
        llm_to_use = llm.bind_tools(tools)
        system_msg = f"""Ты ассистент по реверс-инжинирингу. Отвечай на русском языке.
Бинарный файл: {state['binary_path']}

ДОСТУПНЫЕ ИНСТРУМЕНТЫ (используй ТОЛЬКО эти, никакие другие):

1. list_functions() - получить список функций. НЕ принимает аргументов.

2. get_decompiled_code_at_address(address) - получить декомпилированный код.
   Пример: address="0x00401000"

3. analyze_binary_structure() - метаданные бинарника. НЕ принимает аргументов.

4. read_memory_bytes(address, size) - прочитать байты памяти.
   Пример: address="0x00402000", size="64"

5. run_python_code(code) - выполнить Python код.

ПРАВИЛА:
- Используй ТОЛЬКО перечисленные выше инструменты
- НЕ выдумывай инструменты (нет disasm, get_function и т.д.)
- Для просмотра кода функции main: сначала list_functions(), найди адрес main, затем get_decompiled_code_at_address(address)"""
    
    messages = state["messages"]
    messages_with_system = [SystemMessage(content=system_msg)] + messages
    response = llm_to_use.invoke(messages_with_system)
    return {"messages": [response]}

def tool_node(state: ReverseEngineeringState):
    """Executes tools requested by the LLM."""
    messages = state["messages"]
    last_message = messages[-1]
    
    tools = {
        "get_decompiled_code_at_address": get_decompiled_code_at_address,
        "analyze_binary_structure": analyze_binary_structure,
        "list_functions": list_functions,
        "run_python_code": run_python_code,
        "read_memory_bytes": read_memory_bytes
    }
    
    outputs = []
    if last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            
            print(f"--- Calling Tool: {tool_name} ---")
            print(f"DEBUG: Tool Arguments: {tool_args}")
            
            if tool_name in tools:
                result = tools[tool_name].invoke(tool_args)
                outputs.append(ToolMessage(
                    content=str(result),
                    tool_call_id=tool_call["id"],
                    name=tool_name
                ))
            else:
                 outputs.append(ToolMessage(
                    content="Error: Tool not found.",
                    tool_call_id=tool_call["id"],
                    name=tool_name
                ))
    
    # Increment tool call counter
    current_count = state.get("tool_call_count", 0)
    return {"messages": outputs, "tool_call_count": current_count + 1}

# --- Conditional Logic ---

def route_initial_step(state: ReverseEngineeringState) -> Literal["analyze", "chatbot"]:
    if state.get("is_report_generated"):
        return "chatbot"
    return "analyze"

def route_chatbot(state: ReverseEngineeringState) -> Literal["tools", "__end__"]:
    messages = state["messages"]
    last_message = messages[-1]
    
    # Check if we've exceeded the tool call limit
    tool_call_count = state.get("tool_call_count", 0)
    MAX_TOOL_CALLS = 30
    
    if tool_call_count >= MAX_TOOL_CALLS:
        print(f"DEBUG: Reached max tool calls ({MAX_TOOL_CALLS}), forcing end")
        return "__end__"
    
    if last_message.tool_calls:
        return "tools"
    return "__end__"

# --- Graph Construction ---

def build_graph():
    workflow = StateGraph(ReverseEngineeringState)

    # Add nodes
    workflow.add_node("analyze", analyze_node)
    workflow.add_node("report", report_node)
    workflow.add_node("chatbot", chatbot_node)
    workflow.add_node("tools", tool_node)

    # Add edges for initialization flow
    workflow.add_conditional_edges(START, route_initial_step)
    workflow.add_edge("analyze", "report")
    workflow.add_edge("report", END) 

    # Add edges for chatbot flow
    workflow.add_conditional_edges("chatbot", route_chatbot)
    workflow.add_edge("tools", "chatbot")

    return workflow.compile()
