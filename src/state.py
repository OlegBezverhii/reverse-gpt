from typing import List, Optional, TypedDict, Annotated
from langchain_core.messages import BaseMessage
import operator

class ReverseEngineeringState(TypedDict):
    """
    State for the Reverse Engineering Agent.
    """
    messages: Annotated[List[BaseMessage], operator.add]
    binary_path: str
    analysis_report: Optional[str]
    current_function_address: Optional[str]
    decompiled_code: Optional[str]
    normalized_code: Optional[str]
    is_report_generated: bool
    tool_call_count: int
