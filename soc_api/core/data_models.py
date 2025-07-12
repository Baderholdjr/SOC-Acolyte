from pydantic import BaseModel, Field
from typing import Dict, Any
import datetime
import uuid

# SQLAlchemy models for the database
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB # Import JSONB
from .database import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_host = Column(String, index=True)
    log_format = Column(String)
    event_time = Column(DateTime, default=datetime.datetime.utcnow)
    raw_log = Column(JSONB) # Changed to JSONB
    parsed_data = Column(JSONB, nullable=True) # Changed to JSONB

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), index=True)
    rule_id = Column(String, index=True)
    severity = Column(String)
    status = Column(String, default="NEW")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    enrichment_data = Column(JSONB, nullable=True) # New column

# Pydantic models for API requests/responses
class LogEntry(BaseModel):
    # ... (no changes to this model)
    source_host: str = Field(..., description="The hostname or IP of the log source.")
    log_format: str = Field(..., description="The format of the log, e.g., 'syslog', 'json', 'cef'.")
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    raw_log: str | Dict[str, Any] = Field(..., description="The raw log message or JSON object.")
