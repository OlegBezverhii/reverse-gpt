import re
import json
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
    get_callers,
    set_binary_path
)
from src.tools.python_tool import run_python_code

# --- Ограничения цикла ---
MAX_TOOL_CALLS = 30
MAX_STAGNANT_STEPS = 3

AGENT_TOOLS = [
    get_decompiled_code_at_address,
    analyze_binary_structure,
    list_functions,
    get_callers,
    run_python_code,
    read_memory_bytes,
]

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
    
    # Проверка счетчиков для предотвращения бесконечных циклов
    tool_call_count = state.get("tool_call_count", 0)
    stagnant_steps = state.get("stagnant_steps", 0)
    
    if tool_call_count >= MAX_TOOL_CALLS or stagnant_steps >= MAX_STAGNANT_STEPS:
        # Принудительный финальный ответ без инструментов
        llm_to_use = llm
        system_msg = """Отвечай на русском языке. 
Ты больше не можешь вызывать инструменты: дальнейшие попытки не дают новой информации.
Дай ФИНАЛЬНЫЙ ответ на основе уже полученной информации. Если чего-то не хватает — честно скажи, что именно не удалось установить."""
    else:
        llm_to_use = llm.bind_tools(AGENT_TOOLS)
        system_msg = f"""Ты — агент для реверс-инжиниринга. Твоя задача — исследовать бинарный файл {state['binary_path']} и отвечать на вопросы.

ПРАВИЛА ИСПОЛЬЗОВАНИЯ ИНСТРУМЕНТОВ:
1. ЗАПРЕЩЕНО выдумывать вывод инструментов. Ты должен РЕАЛЬНО вызвать функцию.
2. ЗАПРЕЩЕНО писать "Результат анализа:", если ты не получил его от инструмента в этом шаге.
3. Если ты не знаешь адрес функции main, вызови `list_functions`.
4. Если тебе нужно увидеть код, вызови `get_decompiled_code_at_address`.
5. Если ты хочешь прочитать память, вызови `read_memory_bytes`.
6. Чтобы узнать, КТО вызывает функцию (перекрёстные ссылки), вызови `get_callers` с её адресом. Не пытайся искать вызывающих перебором — используй `get_callers`.

ЗАПРЕТ НА ЗАЦИКЛИВАНИЕ:
- НЕ вызывай инструмент с теми же аргументами повторно. Если результат уже был получен — используй его.
- Если инструмент вернул ошибку или пустой результат, НЕ повторяй тот же вызов. Смени адрес, подход или инструмент.
- Если два-три шага подряд не дают новой информации — прекрати исследование и синтезируй ответ из того, что уже известно.

АЛГОРИТМ:
1. Пойми, что нужно пользователю.
2. Выбери нужный инструмент.
3. ВЫЗОВИ инструмент (через tool_calls).
4. ОСТАНОВИСЬ и жди результата. НЕ ПИШИ, что вернул инструмент, пока система не передаст тебе результат.

Отвечай на русском языке."""
    
    messages = _repair_tool_messages(state["messages"])
    messages_with_system = [SystemMessage(content=system_msg)] + messages
    response = llm_to_use.invoke(messages_with_system)
    return {"messages": [response]}

def _call_signature(tool_name: str, tool_args: dict) -> str:
    """Стабильный ключ вызова инструмента для дедупликации."""
    try:
        args_repr = json.dumps(tool_args, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        args_repr = str(tool_args)
    return f"{tool_name}:{args_repr}"

# LLM иногда пишет hex-числа (0x100) или висячие запятые — это не валидный JSON.
_HEX_LITERAL_RE = re.compile(r'(?<![\w"])0x([0-9a-fA-F]+)')
_TRAILING_COMMA_RE = re.compile(r',\s*([}\]])')

def _repair_json_args(raw_args):
    """Пытается восстановить нестрогий JSON из аргументов tool_call (hex, висячие запятые)."""
    if isinstance(raw_args, dict):
        return raw_args
    if not isinstance(raw_args, str):
        return None
    candidate = _HEX_LITERAL_RE.sub(lambda m: str(int(m.group(1), 16)), raw_args)
    candidate = _TRAILING_COMMA_RE.sub(r'\1', candidate)
    try:
        parsed = json.loads(candidate)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None

def _execute_tool(tool_name, tool_args, call_id, tools, history):
    """Выполняет один вызов с дедупликацией. Возвращает (ToolMessage, progressed)."""
    signature = _call_signature(tool_name, tool_args)
    if signature in history:
        print("DEBUG: Повторный вызов с теми же аргументами — пропущен.")
        return ToolMessage(
            content=(
                "DUPLICATE CALL: ты уже вызывал этот инструмент с точно такими же "
                "аргументами. Повторный вызов не выполнен. Вот результат, полученный ранее:\n"
                f"{history[signature]}\n\n"
                "НЕ повторяй этот вызов. Смени аргументы/подход или, если данных достаточно, "
                "дай итоговый ответ."
            ),
            tool_call_id=call_id,
            name=tool_name,
        ), False
    if tool_name in tools:
        result = str(tools[tool_name].invoke(tool_args))
    else:
        result = "Ошибка: Инструмент не найден."
    history[signature] = result
    return ToolMessage(content=result, tool_call_id=call_id, name=tool_name), True

def _iter_tool_call_ids(msg):
    """Возвращает (id, name) для всех tool_call, включая невалидные."""
    for tc in (getattr(msg, "tool_calls", None) or []):
        yield tc.get("id"), tc.get("name")
    for tc in (getattr(msg, "invalid_tool_calls", None) or []):
        yield tc.get("id"), tc.get("name")

def _has_pending_tool_calls(msg) -> bool:
    return bool(getattr(msg, "tool_calls", None) or getattr(msg, "invalid_tool_calls", None))

def _repair_tool_messages(messages):
    """Страховка: на каждый assistant.tool_calls должен быть tool-ответ.
    Иначе DeepSeek отклоняет запрос ('insufficient tool messages following tool_calls')."""
    repaired = []
    i = 0
    total = len(messages)
    while i < total:
        msg = messages[i]
        if isinstance(msg, AIMessage) and _has_pending_tool_calls(msg):
            calls = list(_iter_tool_call_ids(msg))
            j = i + 1
            following = {}
            while j < total and isinstance(messages[j], ToolMessage):
                following[messages[j].tool_call_id] = messages[j]
                j += 1
            repaired.append(msg)
            for call_id, call_name in calls:
                if call_id in following:
                    repaired.append(following.pop(call_id))
                else:
                    repaired.append(ToolMessage(
                        content="ERROR: tool call was not executed. Rephrase the call with valid arguments.",
                        tool_call_id=call_id,
                        name=call_name or "unknown",
                    ))
            i = j
        elif isinstance(msg, ToolMessage):
            # Осиротевший tool-ответ без предшествующего tool_call — отбрасываем
            i += 1
        else:
            repaired.append(msg)
            i += 1
    return repaired

def tool_node(state: ReverseEngineeringState):
    """Выполняет инструменты, запрошенные LLM. Повторные одинаковые вызовы не выполняются."""
    messages = state["messages"]
    last_message = messages[-1]
    
    tools = {
        "get_decompiled_code_at_address": get_decompiled_code_at_address,
        "analyze_binary_structure": analyze_binary_structure,
        "list_functions": list_functions,
        "get_callers": get_callers,
        "run_python_code": run_python_code,
        "read_memory_bytes": read_memory_bytes
    }
    
    history = dict(state.get("tool_history") or {})
    outputs = []
    made_progress = False
    
    # Валидные вызовы инструментов
    for tool_call in (getattr(last_message, "tool_calls", None) or []):
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]
        
        print(f"--- Вызов инструмента: {tool_name} ---")
        print(f"DEBUG: Аргументы инструмента: {tool_args}")
        
        tool_message, progressed = _execute_tool(tool_name, tool_args, tool_call["id"], tools, history)
        outputs.append(tool_message)
        made_progress = made_progress or progressed
    
    # Невалидные вызовы (битый JSON аргументов). Сначала пытаемся починить (например 0x100),
    # иначе отвечаем ошибкой — но в любом случае закрываем каждый tool_call_id.
    for bad_call in (getattr(last_message, "invalid_tool_calls", None) or []):
        bad_name = bad_call.get("name") or "unknown"
        repaired_args = _repair_json_args(bad_call.get("args"))
        
        if repaired_args is not None and bad_name in tools:
            print(f"--- Восстановлен невалидный вызов: {bad_name} -> {repaired_args} ---")
            tool_message, progressed = _execute_tool(bad_name, repaired_args, bad_call.get("id"), tools, history)
            outputs.append(tool_message)
            made_progress = made_progress or progressed
        else:
            bad_error = bad_call.get("error") or "invalid arguments"
            print(f"--- Невалидный вызов инструмента: {bad_name} ({bad_error}) ---")
            outputs.append(ToolMessage(
                content=(
                    f"ERROR: не удалось разобрать аргументы вызова '{bad_name}' ({bad_error}). "
                    "Вызови инструмент заново с корректным JSON. Числа указывай в десятичном виде "
                    "(например, 256, а не 0x100)."
                ),
                tool_call_id=bad_call.get("id"),
                name=bad_name,
            ))
    
    # Сброс счетчика застоя при наличии нового успешного вызова
    stagnant_steps = state.get("stagnant_steps", 0)
    if made_progress:
        stagnant_steps = 0
    elif _has_pending_tool_calls(last_message):
        stagnant_steps += 1
    
    current_count = state.get("tool_call_count", 0)
    return {
        "messages": outputs,
        "tool_call_count": current_count + 1,
        "tool_history": history,
        "stagnant_steps": stagnant_steps,
    }

# --- Условная логика ---

def route_initial_step(state: ReverseEngineeringState) -> Literal["analyze", "chatbot"]:
    if state.get("is_report_generated"):
        return "chatbot"
    return "analyze"

def route_chatbot(state: ReverseEngineeringState) -> Literal["tools", "__end__"]:
    messages = state["messages"]
    last_message = messages[-1]
    
    # Всегда сначала закрываем незавершённые tool_calls, иначе DeepSeek вернёт 400
    # и assistant с tool_calls «зависнет» без ответов.
    if _has_pending_tool_calls(last_message):
        return "tools"
    
    # Проверка превышения лимитов (безопасна: tool_calls уже обработаны выше)
    tool_call_count = state.get("tool_call_count", 0)
    stagnant_steps = state.get("stagnant_steps", 0)
    
    if tool_call_count >= MAX_TOOL_CALLS:
        print(f"DEBUG: Достигнут лимит вызовов ({MAX_TOOL_CALLS}), принудительное завершение")
    elif stagnant_steps >= MAX_STAGNANT_STEPS:
        print(f"DEBUG: Нет прогресса {stagnant_steps} шагов подряд, принудительное завершение")
    
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