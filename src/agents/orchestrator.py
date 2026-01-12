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

# --- Определения узлов ---

def analyze_node(state: ReverseEngineeringState):
    """Выполняет начальный анализ бинарного файла."""
    print("--- Шаг 1: Анализ бинарного файла ---")
    path = state["binary_path"]
    set_binary_path(path)
    analysis = _analyze_binary_structure.invoke({"file_path": path})
    return {"analysis_report": analysis}

def fetch_code_node(state: ReverseEngineeringState):
    """Получает начальный декомпилированный код (например, из точки входа)."""
    print("--- Шаг 2: Получение декомпилированного кода ---")
    path = state["binary_path"]
    # Извлечение точки входа из анализа или использование значения по умолчанию
    entry = state.get("current_function_address")
    
    if not entry:
        # Попытка извлечь точку входа из отчета анализа
        report = state.get("analysis_report", "")
        match = re.search(r"Entry Point: \s*([0-9a-fA-Fx]+)", report, re.IGNORECASE)
        if match:
            entry = match.group(1)
        else:
            entry = "0x401050" # Запасной вариант
            
    print(f"DEBUG: Используется точка входа: {entry}")
    code = get_decompiled_code_at_address.invoke({"address": entry, "file_path": path})
    
    # Если функция не найдена по точке входа, попытаться найти любую функцию
    if "No function found at" in code:
        print(f"DEBUG: Функция по адресу {entry} не найдена, получение списка доступных функций...")
        functions_list = list_functions.invoke({"file_path": path})
        print(f"DEBUG: Доступные функции: {functions_list}")
        
        # Попытка извлечь адрес первой функции из списка
        func_match = re.search(r"(0x[0-9a-fA-F]+):", functions_list)
        if func_match:
            first_func_addr = func_match.group(1)
            print(f"DEBUG: Пробуем первую доступную функцию по адресу {first_func_addr}")
            code = get_decompiled_code_at_address.invoke({"address": first_func_addr, "file_path": path})
        else:
            code = f"Не удалось найти ни одной функции в бинарном файле. Доступные функции:\n{functions_list}"
    
    return {"decompiled_code": code}

def report_node(state: ReverseEngineeringState):
    """Генерирует начальный отчет."""
    print("--- Шаг 3: Генерация отчета ---")
    analysis = state["analysis_report"]
    
    report = f"""# Анализ бинарного файла

{analysis}

Файл готов к анализу. Задавайте вопросы о функциях, коде или структуре бинарного файла."""
    
    return {"messages": [AIMessage(content=report)], "is_report_generated": True}

def chatbot_node(state: ReverseEngineeringState):
    """
    Обрабатывает взаимодействие с пользователем после генерации отчета.
    Принимает решение о вызове инструментов или прямом ответе.
    """
    # Убедиться, что путь к бинарному файлу установлен для инструментов
    set_binary_path(state['binary_path'])
    
    llm = get_llm()
    tools = [get_decompiled_code_at_address, analyze_binary_structure, list_functions, run_python_code, read_memory_bytes]
    
    # Проверка счетчика вызовов инструментов для предотвращения бесконечных циклов
    tool_call_count = state.get("tool_call_count", 0)
    MAX_TOOL_CALLS = 30
    
    if tool_call_count >= MAX_TOOL_CALLS:
        # Принудительный финальный ответ без инструментов
        llm_to_use = llm
        system_msg = """Отвечай на русском языке. 
Ты достиг лимита вызовов инструментов. Дай ФИНАЛЬНЫЙ ответ на основе имеющейся информации."""
    else:
        llm_to_use = llm.bind_tools(tools)
        system_msg = f"""Ты — агент для реверс-инжиниринга. Твоя задача — исследовать бинарный файл {state['binary_path']} и отвечать на вопросы.

ПРАВИЛА ИСПОЛЬЗОВАНИЯ ИНСТРУМЕНТОВ:
1. ЗАПРЕЩЕНО выдумывать вывод инструментов. Ты должен РЕАЛЬНО вызвать функцию.
2. ЗАПРЕЩЕНО писать "Результат анализа:", если ты не получил его от инструмента в этом шаге.
3. Если ты не знаешь адрес функции main, вызови `list_functions`.
4. Если тебе нужно увидеть код, вызови `get_decompiled_code_at_address`.
5. Если ты хочешь прочитать память, вызови `read_memory_bytes`.

АЛГОРИТМ:
1. Пойми, что нужно пользователю.
2. Выбери нужный инструмент.
3. ВЫЗОВИ инструмент (через tool_calls).
4. ОСТАНОВИСЬ и жди результата. НЕ ПИШИ, что вернул инструмент, пока система не передаст тебе результат.

Отвечай на русском языке."""
    
    messages = state["messages"]
    messages_with_system = [SystemMessage(content=system_msg)] + messages
    response = llm_to_use.invoke(messages_with_system)
    return {"messages": [response]}

def tool_node(state: ReverseEngineeringState):
    """Выполняет инструменты, запрошенные LLM."""
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
            
            print(f"--- Вызов инструмента: {tool_name} ---")
            print(f"DEBUG: Аргументы инструмента: {tool_args}")
            
            if tool_name in tools:
                result = tools[tool_name].invoke(tool_args)
                outputs.append(ToolMessage(
                    content=str(result),
                    tool_call_id=tool_call["id"],
                    name=tool_name
                ))
            else:
                 outputs.append(ToolMessage(
                    content="Ошибка: Инструмент не найден.",
                    tool_call_id=tool_call["id"],
                    name=tool_name
                ))
    
    # Увеличение счетчика вызовов
    current_count = state.get("tool_call_count", 0)
    return {"messages": outputs, "tool_call_count": current_count + 1}

# --- Условная логика ---

def route_initial_step(state: ReverseEngineeringState) -> Literal["analyze", "chatbot"]:
    if state.get("is_report_generated"):
        return "chatbot"
    return "analyze"

def route_chatbot(state: ReverseEngineeringState) -> Literal["tools", "__end__"]:
    messages = state["messages"]
    last_message = messages[-1]
    
    # Проверка превышения лимита вызовов инструментов
    tool_call_count = state.get("tool_call_count", 0)
    MAX_TOOL_CALLS = 30
    
    if tool_call_count >= MAX_TOOL_CALLS:
        print(f"DEBUG: Достигнут лимит вызовов ({MAX_TOOL_CALLS}), принудительное завершение")
        return "__end__"
    
    if last_message.tool_calls:
        return "tools"
    return "__end__"

# --- Построение графа ---

def build_graph():
    workflow = StateGraph(ReverseEngineeringState)

    # Добавление узлов
    workflow.add_node("analyze", analyze_node)
    workflow.add_node("report", report_node)
    workflow.add_node("chatbot", chatbot_node)
    workflow.add_node("tools", tool_node)

    # Добавление ребер для процесса инициализации
    workflow.add_conditional_edges(START, route_initial_step)
    workflow.add_edge("analyze", "report")
    workflow.add_edge("report", END) 

    # Добавление ребер для чат-бота
    workflow.add_conditional_edges("chatbot", route_chatbot)
    workflow.add_edge("tools", "chatbot")

    return workflow.compile()