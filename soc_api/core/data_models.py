from pydantic import BaseModel, Field, field_validator
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import uuid

# SQLAlchemy models for the database
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from .database import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_host = Column(String, index=True)
    log_format = Column(String)
    event_time = Column(DateTime(timezone=True))
    raw_log = Column(JSONB)
    parsed_data = Column(JSONB, nullable=True)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id = Column(UUID(as_uuid=True), index=True)
    rule_id = Column(String, index=True)
    severity = Column(String)
    status = Column(String, default="NEW")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), onupdate=lambda: datetime.now(timezone.utc))
    enrichment_data = Column(JSONB, nullable=True)

# --- Pydantic Models ---

class LogEntry(BaseModel):
    source_host: str
    log_format: str
    timestamp: datetime
    raw_log: str | Dict[str, Any]

class AlertResponse(BaseModel):
    id: uuid.UUID
    event_id: uuid.UUID
    rule_id: str
    severity: str
    status: str
    created_at: datetime
    updated_at: Optional[datetime] = None
    enrichment_data: Optional[Dict[str, Any]] = None
    class Config:
        from_attributes = True

class AlertStatusUpdateRequest(BaseModel):
    status: str
    @field_validator('status')
    def status_must_be_valid(cls, v):
        valid_statuses = ['NEW', 'INVESTIGATING', 'CLOSED']
        if v.upper() not in valid_statuses:
            raise ValueError(f'Status must be one of: {valid_statuses}')
        return v.upper()

class AnonymizedAlertPayload(BaseModel):
    anonymized_asset_id: str
    alert_type: str
    severity: str
    event_time: datetime
    raw_data: Dict[str, Any]

class InquisitorDataPackage(BaseModel):
    alerts: List[AnonymizedAlertPayload]
    metrics: Optional[List[Any]] = None

class AlertSummaryResponse(BaseModel):
    total_alerts: int
    new_alerts: int
    by_severity: Dict[str, int]