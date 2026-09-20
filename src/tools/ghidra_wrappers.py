from langchain_core.tools import tool
from typing import Union
from src.tools.ghidra import (
    get_decompiled_code_at_address as _get_decompiled_code,
    list_functions as _list_functions,
    analyze_binary_structure as _analyze_binary,
    read_memory_bytes as _read_memory,
    get_callers as _get_callers
)

# Global variable to store current binary path
_current_binary_path = None

def set_binary_path(path: str):
    """Set the current binary path for all tools."""
    global _current_binary_path
    _current_binary_path = path

@tool
def get_decompiled_code_at_address(address: str) -> str:
    """
    Retrieves the decompiled C code from Ghidra for a specific function address.
    
    Args:
        address: The hex address of the function (e.g., "0x00401000").
    """
    return _get_decompiled_code.invoke({"address": address, "file_path": _current_binary_path})

@tool
def list_functions() -> str:
    """
    Lists all functions found in the binary file with their addresses.
    """
    return _list_functions.invoke({"file_path": _current_binary_path})

@tool
def analyze_binary_structure() -> str:
    """
    Performs static analysis of the binary file to extract metadata.
    Returns architecture, entry point, sections, and function count.
    """
    return _analyze_binary.invoke({"file_path": _current_binary_path})

@tool
def get_callers(address: str) -> str:
    """
    Finds all cross-references (callers) TO a function or address.
    Use this to answer questions like "which function calls FUN_0041b3e0?".

    Args:
        address: The hex address of the function or code location (e.g., "0x0041b3e0").
    """
    return _get_callers.invoke({"address": address, "file_path": _current_binary_path})

@tool
def read_memory_bytes(address: str, size: Union[int, str] = "0") -> str:
    """
    Reads memory bytes from the binary at a specific address.
    Useful for inspecting DAT_ variables, strings, or arrays.
    
    Args:
        address: The hex address to read from (e.g., "0x00402000").
        size: Number of bytes to read as a decimal integer (e.g., 64, 256).
              If 0, tries to detect size based on defined data.
    """
    return _read_memory.invoke({"address": address, "size": size, "file_path": _current_binary_path})
