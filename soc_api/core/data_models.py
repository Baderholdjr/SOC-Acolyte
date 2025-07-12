from pydantic import BaseModel, Field
from typing import Dict, Any
import datetime
import uuid

# SQLAlchemy models for the database
from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
from .database import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_host = Column(String, index=True)
    log_format = Column(String)
    event_time = Column(DateTime, default=datetime.datetime.utcnow)
    raw_log = Column(JSON)
    # This would be populated by a parsing engine
    parsed_data = Column(JSON, nullable=True)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), index=True)
    rule_id = Column(String, index=True) # e.g., "SOC-RULE-001"
    severity = Column(String) # e.g., "LOW", "MEDIUM", "CRITICAL"
    status = Column(String, default="NEW") # NEW, INVESTIGATING, CLOSED
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


# Pydantic models for API requests/responses
class LogEntry(BaseModel):
    """
    Represents a single, generic log entry received by the Acolyte.
    """
    source_host: str = Field(..., description="The hostname or IP of the log source.")
    log_format: str = Field(..., description="The format of the log, e.g., 'syslog', 'json', 'cef'.")
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    raw_log: str | Dict[str, Any] = Field(..., description="The raw log message or JSON object.")
