from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from .database import Base
import uuid
from datetime import datetime, timezone

class ResponseAction(Base):
    """
    Represents a response action to be taken for a specific alert.
    This table tracks the what, when, and for which alert an action is intended.
    """
    __tablename__ = "response_actions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False)
    action_type = Column(String, nullable=False) # e.g., "BLOCK_IP", "ISOLATE_HOST"
    parameters = Column(JSONB, nullable=True) # e.g., {"ip_address": "1.2.3.4"}
    status = Column(String, default="PENDING") # PENDING, COMPLETED, FAILED
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    executed_at = Column(DateTime(timezone=True), nullable=True)

    # Establish a relationship to the Alert model
    alert = relationship("Alert")

class ResponseActionExecution(Base):
    """
    Logs the result of each individual execution of a response action.
    This provides an audit trail of what happened when an action was triggered.
    """
    __tablename__ = "response_action_executions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    action_id = Column(UUID(as_uuid=True), ForeignKey("response_actions.id"), nullable=False)
    status = Column(String, nullable=False) # SUCCESS, FAILURE
    result = Column(JSONB, nullable=True) # Detailed results, e.g., API response from a firewall
    executed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Establish a relationship to the ResponseAction model
    action = relationship("ResponseAction")