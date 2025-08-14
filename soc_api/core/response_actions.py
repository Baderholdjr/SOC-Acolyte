from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from .database import Base
import uuid
from datetime import datetime, timezone

class ResponseAction(Base):
    __tablename__ = "response_actions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False)
    action_type = Column(String, nullable=False)
    parameters = Column(JSONB, nullable=True)
    status = Column(String, default="PENDING")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    executed_at = Column(DateTime(timezone=True), nullable=True)

    alert = relationship("Alert", back_populates="response_actions")
    # --- ADDED: Relationship to executions ---
    executions = relationship("ResponseActionExecution", back_populates="action", cascade="all, delete-orphan")

class ResponseActionExecution(Base):
    __tablename__ = "response_action_executions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action_id = Column(UUID(as_uuid=True), ForeignKey("response_actions.id"), nullable=False)
    status = Column(String, nullable=False)
    result = Column(JSONB, nullable=True)
    executed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    action = relationship("ResponseAction", back_populates="executions")
