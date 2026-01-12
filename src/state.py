from typing import List, Optional, TypedDict, Annotated
from langchain_core.messages import BaseMessage
import operator

class ReverseEngineeringState(TypedDict):
    messages: Annotated[List[BaseMessage], "История сообщений чата"]
    binary_path: str
    is_report_generated: bool
    
    analysis_report: Optional[str]
    current_function_address: Optional[str]
    decompiled_code: Optional[str]
    normalized_code: Optional[str]
    
    tool_call_count: int