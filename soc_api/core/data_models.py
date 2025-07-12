from pydantic import BaseModel, Field
from typing import Dict, Any
import datetime

class LogEntry(BaseModel):
    """
    Represents a single, generic log entry received by the Acolyte.
    This model is flexible to accommodate various log source formats.
    """
    source_host: str = Field(..., description="The hostname or IP of the log source.")
    log_format: str = Field(..., description="The format of the log, e.g., 'syslog', 'json', 'cef'.")
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    raw_log: str | Dict[str, Any] = Field(..., description="The raw log message or JSON object.")

