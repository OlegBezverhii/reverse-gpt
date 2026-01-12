import os
import sys
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from src.agents.orchestrator import build_graph
from rich.console import Console
from rich.markdown import Markdown

console = Console()

def main():
    # Load environment variables
    load_dotenv()
    
    # Check for API Key
    if not os.getenv("GIGACHAT_CREDENTIALS"):
        console.print("[red]Error: GIGACHAT_CREDENTIALS not found in environment variables.[/red]")
        console.print("Please create a .env file with your credentials or export it.")
        key = input("Or enter it now: ").strip()
        if key:
            os.environ["GIGACHAT_CREDENTIALS"] = key
        else:
            sys.exit(1)

    console.print("[bold cyan]Welcome to Reverse-GPT CLI[/bold cyan]")
    console.print("-" * 50)

    # 1. Get Binary Path
    binary_path = input("Enter the path to the binary file to analyze: ").strip()
    if not binary_path:
        console.print("[red]No path provided. Exiting.[/red]")
        sys.exit(1)
    
    # Initialize the graph
    app = build_graph()
    
    # Initial State
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

    console.print("\n[yellow]--- Starting Initial Analysis ---[/yellow]")
    
    # Run the graph until the report is generated (first pass)
    final_state = app.invoke(state)
    
    console.print("\n[bold green]--- Initial Report ---[/bold green]")
    md = Markdown(final_state["messages"][-1].content)
    console.print(md)
    console.print("-" * 50 + "\n")
    
    # Update our local state with the result of the first pass
    state = final_state
    
    # Interactive Loop
    console.print("[cyan]You can now ask questions about the binary. Type 'exit' or 'quit' to stop.[/cyan]")
    while True:
        try:
            user_input = console.input("\n[bold blue]User:[/bold blue] ").strip()
            if user_input.lower() in ["exit", "quit"]:
                break
            
            # Append user message to state
            state["messages"].append(HumanMessage(content=user_input))
            # Reset tool call counter for new question
            state["tool_call_count"] = 0
            
            # Run the graph
            final_state = app.invoke(state, {"recursion_limit": 100})
            
            # Get the last AI response
            last_msg = final_state["messages"][-1]
            console.print("\n[bold green]AI:[/bold green]")
            md = Markdown(last_msg.content)
            console.print(md)
            
            # Update state for next turn
            state = final_state
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Exiting...[/yellow]")
            break
        except Exception as e:
            console.print(f"\n[red]An error occurred: {e}[/red]")

if __name__ == "__main__":
    main()