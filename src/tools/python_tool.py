import sys
import io
import traceback
from langchain_core.tools import tool

@tool
def run_python_code(code: str) -> str:
    """
    Executes the provided Python code and returns the standard output and standard error.
    Use this for simple calculations or string decoding (e.g. XOR).
    
    WARNING: 
    - Do NOT use this to read/parse the binary file directly. Use `read_memory_bytes` instead.
    - Keep the code SHORT and simple to avoid JSON parsing errors.
    - Ensure correct escaping of quotes and newlines.
    
    Args:
        code: The Python code to execute.
    """
    # Create a buffer to capture stdout and stderr
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    
    # Save original stdout/stderr
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    
    try:
        # Redirect stdout/stderr
        sys.stdout = stdout_buffer
        sys.stderr = stderr_buffer
        
        # execution environment
        exec_globals = {}
        
        # Execute the code
        exec(code, exec_globals)
        
        output = stdout_buffer.getvalue()
        error = stderr_buffer.getvalue()
        
        result = ""
        if output:
            result += f"Stdout:\n{output}\n"
        if error:
            result += f"Stderr:\n{error}\n"
            
        if not result:
            result = "Code executed successfully with no output."
            
        return result
        
    except Exception:
        return f"Error executing code:\n{traceback.format_exc()}"
        
    finally:
        # Restore stdout/stderr
        sys.stdout = original_stdout
        sys.stderr = original_stderr
