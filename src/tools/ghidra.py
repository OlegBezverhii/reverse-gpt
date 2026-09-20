from langchain_core.tools import tool
import pyhidra
from pathlib import Path
import threading
import shutil
import atexit
import os
from typing import Optional, Union

pyhidra.start()

from ghidra.base.project import GhidraProject

_lock = threading.Lock()
_current_context = None
_force_reanalyze = False

def close_context():
    """Аккуратно закрывает открытый проект Ghidra и останавливает JVM.
    Без этого фоновые потоки Ghidra не дают процессу завершиться."""
    global _current_context
    with _lock:
        if _current_context is not None:
            try:
                _current_context[1].__exit__(None, None, None)
            except Exception as e:
                print(f"Warning: Failed to close Ghidra context: {e}")
            finally:
                _current_context = None

        try:
            import jpype
            if jpype.isJVMStarted():
                jpype.shutdownJVM()
        except Exception as e:
            print(f"Warning: Failed to shut down JVM: {e}")

atexit.register(close_context)

def set_reanalyze(flag: bool):
    """Принудительно пересоздать проект и заново проанализировать бинарник."""
    global _force_reanalyze
    _force_reanalyze = bool(flag)

def _project_paths(file_path: str):
    project_root = Path.cwd() / ".ghidra_projects"
    project_name = Path(file_path).name + "_ghidra"
    real_project_location = project_root / project_name
    return project_root, project_name, real_project_location

def project_exists(file_path: str) -> bool:
    """Проверяет, есть ли уже сохранённый проект Ghidra для этого файла."""
    project_root, project_name, real_project_location = _project_paths(file_path)
    gpr = real_project_location / f"{project_name}.gpr"
    rep = real_project_location / f"{project_name}.rep"
    return gpr.exists() and rep.exists()

def _clean_project_files(project_root: Path, project_name: str, real_project_location: Path):
    """Удаляет артефакты проекта (нужно только при пересоздании)."""
    possible_paths = [
        real_project_location,                  # директория проекта целиком
        project_root / f"{project_name}.gpr",
        project_root / f"{project_name}.rep",
        project_root / f"{project_name}.lock",
        project_root / f"{project_name}.lock~",
    ]
    for p in possible_paths:
        try:
            if p.exists():
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
        except Exception as e:
            print(f"Warning: Failed to cleanup {p}: {e}")

def _remove_stale_locks(real_project_location: Path, project_name: str):
    """Убирает осиротевшие lock-файлы от предыдущих неудачных запусков."""
    for name in (f"{project_name}.lock", f"{project_name}.lock~"):
        p = real_project_location / name
        try:
            if p.exists():
                p.unlink()
        except Exception as e:
            print(f"Warning: Failed to remove lock {p}: {e}")

def _precreate_project(real_project_location: Path, project_name: str):
    """pyhidra не ловит NotFoundException при открытии несуществующего проекта."""
    real_project_location.mkdir(exist_ok=True, parents=True)
    try:
        p = GhidraProject.createProject(str(real_project_location), project_name, False)
        p.close()
    except Exception as e:
        print(f"Warning: Failed to pre-create project: {e}")

def _get_context(file_path: str):
    global _current_context
    with _lock:
        if _current_context is None or _current_context[0] != file_path:
            if _current_context:
                try:
                    _current_context[1].__exit__(None, None, None)
                except Exception as e:
                    print(f"Warning: Failed to close previous Ghidra context: {e}")
                _current_context = None

            project_root, project_name, real_project_location = _project_paths(file_path)
            project_root.mkdir(exist_ok=True)

            reuse = False
            if _force_reanalyze:
                print("Принудительный повторный анализ: пересоздаю проект Ghidra...")
            elif project_exists(file_path):
                # Проект уже есть — открываем базу без повторного импорта и анализа
                _remove_stale_locks(real_project_location, project_name)
                reuse = True
                print(f"Открываю существующий проект Ghidra (без повторного анализа): {real_project_location}")

            if not reuse:
                _clean_project_files(project_root, project_name, real_project_location)
                _precreate_project(real_project_location, project_name)

            def _open():
                ctx = pyhidra.open_program(
                    file_path,
                    project_location=str(project_root),
                    project_name=project_name,
                    analyze=True,  # pyhidra пропустит анализ, если программа уже проанализирована
                )
                return ctx, ctx.__enter__()

            try:
                ctx, flat_api = _open()
            except Exception as e:
                if not reuse:
                    raise
                print(f"Warning: не удалось открыть существующий проект ({e}). Пересоздаю с анализом...")
                _clean_project_files(project_root, project_name, real_project_location)
                _precreate_project(real_project_location, project_name)
                ctx, flat_api = _open()

            # Initialize decompiler properly
            from ghidra.app.decompiler import DecompInterface
            decomp = DecompInterface()
            decomp.openProgram(flat_api.getCurrentProgram())

            _current_context = (file_path, ctx, flat_api, decomp)
        return _current_context[2], _current_context[3]

@tool
def get_decompiled_code_at_address(address: str, file_path: str = None) -> str:
    """
    Retrieves the decompiled C code from Ghidra for a specific function address.
    
    Args:
        address: The hex address of the function (e.g., "0x00401000").
    """
        
    flat_api, decomp = _get_context(file_path)
    addr = flat_api.toAddr(int(address, 16))
    func = flat_api.getFunctionContaining(addr)
    if not func:
        return f"No function found at {address}"
    
    try:
        # Try the correct method name
        res = decomp.decompileFunction(func, 30, None)  # 30 second timeout
        if res and res.getDecompiledFunction():
            return res.getDecompiledFunction().getC()
        else:
            return "Decompilation failed - no result"
    except AttributeError:
        # Fallback to alternative API
        try:
            from ghidra.app.decompiler import DecompInterface
            decompiler = DecompInterface()
            decompiler.openProgram(flat_api.getCurrentProgram())
            res = decompiler.decompileFunction(func, 30, None)
            if res and res.getDecompiledFunction():
                return res.getDecompiledFunction().getC()
            else:
                return "Decompilation failed - alternative method"
        except Exception as e:
            return f"Decompilation failed: {str(e)}"

@tool
def get_callers(address: str, file_path: str = None) -> str:
    """
    Finds all functions that CALL the given function/address (call cross-references).
    Use this to answer questions like "which function calls FUN_0041b3e0?".

    Args:
        address: The hex address of the function or code location (e.g., "0x0041b3e0").
    """
    try:
        flat_api, _ = _get_context(file_path)

        try:
            addr = flat_api.toAddr(int(address, 16))
        except ValueError:
            return f"Error: Invalid address format '{address}'"

        func = flat_api.getFunctionContaining(addr)
        target_addr = func.getEntryPoint() if func else addr
        target_name = func.getName() if func else address

        try:
            references = flat_api.getReferencesTo(target_addr)
        except AttributeError:
            references = flat_api.getCurrentProgram().getReferenceManager().getReferencesTo(target_addr)

        callers = {}
        for ref in references:
            # Интересуют только реальные вызовы, а не ветвления/данные
            if not ref.getReferenceType().isCall():
                continue
            call_address = ref.getFromAddress()
            caller = flat_api.getFunctionContaining(call_address)
            if caller is None:
                continue
            key = str(caller.getEntryPoint())
            if key not in callers:
                callers[key] = (caller.getName(), [])
            callers[key][1].append(str(call_address))

        if not callers:
            return f"No callers (call xrefs) found for {target_name} at {target_addr}."

        lines = [f"Callers of {target_name} ({target_addr}): {len(callers)} function(s)."]
        for entry, (name, sites) in callers.items():
            lines.append(f"- {name} @ {entry} (call sites: {', '.join(sites)})")
        return "\n".join(lines)
    except Exception as e:
        return f"Error getting callers: {str(e)}"

@tool
def list_functions(file_path: str = None) -> str:
    """
    Lists all functions found in the binary file with their addresses.
    """

    flat_api, _ = _get_context(file_path)
    program = flat_api.getCurrentProgram()
    func_manager = program.getFunctionManager()
    
    functions = []
    func_iter = func_manager.getFunctions(True)  # True for forward iteration
    
    count = 0
    for func in func_iter:
        if count >= 20:  # Limit to first 20 functions to avoid overwhelming output
            functions.append("... (showing first 20 functions)")
            break
        functions.append(f"{func.getEntryPoint()}: {func.getName()}")
        count += 1
    
    if not functions:
        return "No functions found in the binary."
    
    return "Functions found:\n" + "\n".join(functions)

@tool
def analyze_binary_structure(file_path: str = None) -> str:
    """
    Performs static analysis of the binary file to extract metadata.
    Returns architecture, entry point, sections, and function count.
    """

    flat_api, _ = _get_context(file_path)
    program = flat_api.getCurrentProgram()
    entry = program.getAddressMap().getImageBase()
    funcs = program.getFunctionManager().getFunctionCount()
    arch = program.getLanguage().getProcessor().toString()
    
    return f"""Binary Analysis for: {file_path}
Architecture: {arch}
Entry Point: {entry}
Functions detected: {funcs}"""

@tool
def read_memory_bytes(address: str, size: Union[int, str] = "0", file_path: str = None) -> str:
    """
    Reads memory bytes from the binary at a specific address.
    Useful for inspecting DAT_ variables, strings, or arrays.
    
    Args:
        address: The hex address to read from (e.g., "0x00402000").
        size: Number of bytes to read as a decimal integer (e.g., 64, 256).
              If 0, tries to detect size based on defined data.
    """

    try:
        flat_api, _ = _get_context(file_path)
        program = flat_api.getCurrentProgram()
        memory = program.getMemory()
        listing = program.getListing()
        
        try:
            addr_obj = flat_api.toAddr(int(address, 16))
        except ValueError:
            return f"Error: Invalid address format '{address}'"

        # Determine size to read
        read_size = 0
        
        # Handle size input (int or hex string)
        if isinstance(size, int):
            read_size = size
        elif isinstance(size, str):
            try:
                if size.strip().lower().startswith("0x"):
                    read_size = int(size, 16)
                else:
                    read_size = int(size)
            except ValueError:
                return f"Error: Invalid size format '{size}'"
        
        data_info = "Raw Bytes"
        
        if read_size <= 0:
            # Check if data is defined at this address
            data = listing.getDataAt(addr_obj)
            if data and not data.isUndefined():
                read_size = data.getLength()
                data_info = f"Defined Data ({data.getDataType().getName()})"
            else:
                read_size = 64  # Default fallback
                data_info = "Undefined Data (Default 64 bytes)"
        
        # Limit max size to prevent huge dumps
        if read_size > 1024:
            read_size = 1024
            data_info += " (Truncated to 1024 bytes)"

        # Read bytes
        # In pyhidra (JPype), we need to create a Java byte array
        import jpype
        buffer = jpype.JArray(jpype.JByte)(read_size)
        
        count = memory.getBytes(addr_obj, buffer)
        
        # Convert signed bytes to unsigned integers for display
        # buffer is a Java array, we can iterate it directly
        unsigned_bytes = [b & 0xFF for b in buffer]
        
        # Format output similar to hexdump
        output = [f"Memory at {address} (Size: {read_size}, Type: {data_info}):"]
        output.append("-" * 60)
        
        hex_lines = []
        ascii_lines = []
        
        for i in range(0, len(unsigned_bytes), 16):
            chunk = unsigned_bytes[i:i+16]
            # Hex part
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            padding = "   " * (16 - len(chunk))
            
            # ASCII part
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            
            output.append(f"{i:04X} | {hex_str}{padding} | {ascii_str}")
            
        return "\n".join(output)

    except Exception as e:
        return f"Error reading memory: {str(e)}"