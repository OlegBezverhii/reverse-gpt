import os
import sys
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from src.agents.orchestrator import build_graph
from rich.console import Console
from rich.markdown import Markdown

console = Console()

def main():
    # Загрузка переменных окружения
    load_dotenv()
    
    # Проверка наличия ключа API
    if not os.getenv("GIGACHAT_CREDENTIALS"):
        console.print("[red]Ошибка: GIGACHAT_CREDENTIALS не найден в переменных окружения.[/red]")
        console.print("Пожалуйста, создайте файл .env с вашими учетными данными или экспортируйте их.")
        key = input("Или введите их сейчас: ").strip()
        if key:
            os.environ["GIGACHAT_CREDENTIALS"] = key
        else:
            sys.exit(1)

    console.print("[bold cyan]Добро пожаловать в Reverse-GPT CLI[/bold cyan]")
    console.print("-" * 50)

    # 1. Получение пути к бинарному файлу
    binary_path = input("Введите путь к анализируемому бинарному файлу: ").strip()
    if not binary_path:
        console.print("[red]Путь не указан. Выход.[/red]")
        sys.exit(1)
    
    # Инициализация графа
    app = build_graph()
    
    # Начальное состояние
    state = {
        "messages": [],
        "binary_path": binary_path,
        "is_report_generated": False,
        "analysis_report": None,
        "current_function_address": None,
        "decompiled_code": None,
        "normalized_code": None,
        "tool_call_count": 0
    }

    console.print("\n[yellow]--- Запуск начального анализа ---[/yellow]")
    
    # Запуск графа до генерации отчета (первый проход)
    final_state = app.invoke(state)
    
    console.print("\n[bold green]--- Начальный отчет ---[/bold green]")
    md = Markdown(final_state["messages"][-1].content)
    console.print(md)
    console.print("-" * 50 + "\n")
    
    # Обновление локального состояния результатом первого прохода
    state = final_state
    
    # Интерактивный цикл
    console.print("[cyan]Теперь вы можете задавать вопросы о бинарном файле. Введите 'exit' или 'quit' для выхода.[/cyan]")
    while True:
        try:
            user_input = console.input("\n[bold blue]Пользователь:[/bold blue] ").strip()
            if user_input.lower() in ["exit", "quit"]:
                break
            
            # Добавление сообщения пользователя в состояние
            state["messages"].append(HumanMessage(content=user_input))
            # Сброс счетчика вызовов инструментов для нового вопроса
            state["tool_call_count"] = 0
            
            # Запуск графа
            final_state = app.invoke(state, {"recursion_limit": 100})
            
            # Получение последнего ответа ИИ
            last_msg = final_state["messages"][-1]
            console.print("\n[bold green]ИИ:[/bold green]")
            md = Markdown(last_msg.content)
            console.print(md)
            
            # Обновление состояния для следующего шага
            state = final_state
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Выход...[/yellow]")
            break
        except Exception as e:
            console.print(f"\n[red]Произошла ошибка: {e}[/red]")

if __name__ == "__main__":
    main()
