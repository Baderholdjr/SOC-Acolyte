from sqlalchemy.orm import Session
from sqlalchemy import and_, String
from . import data_models as models
from .cti_service import CTIService  # Import the new service
import datetime
import uuid


class RulesEngine:
    """
    Analyzes security events and generates alerts based on predefined rules.
    """

    def __init__(self, db: Session):
        self.db = db
        self.cti_service = CTIService(db)  # Initialize the CTI service

    async def run_engine_for_host(self, source_host: str):
        """
        Runs all defined rules for a specific source host.
        """
        print(f"Running rules engine for host: {source_host}")
        await self._rule_001_multiple_failed_logins(source_host)

    async def _rule_001_multiple_failed_logins(self, source_host: str):
        """
        Rule: Detects 5 or more failed logins from the same source host
        within a 5-minute window.
        """
        rule_id = "SOC-RULE-001"
        time_window = datetime.timedelta(minutes=5)
        failure_threshold = 5

        recent_failed_logins = self.db.query(models.SecurityEvent).filter(
            models.SecurityEvent.source_host == source_host,
            models.SecurityEvent.raw_log.cast(String).ilike('%login_failed%'),
            models.SecurityEvent.event_time >= datetime.datetime.utcnow() - time_window
        ).all()

        if len(recent_failed_logins) >= failure_threshold:
            latest_event_id = max(event.id for event in recent_failed_logins)

            existing_alert = self.db.query(models.Alert).filter(
                models.Alert.rule_id == rule_id,
                models.Alert.event_id == latest_event_id
            ).first()

            if existing_alert:
                return

            new_alert = models.Alert(
                id=uuid.uuid4(),
                event_id=latest_event_id,
                rule_id=rule_id,
                severity="MEDIUM",
                status="NEW"
            )
            self.db.add(new_alert)
            self.db.commit()
            self.db.refresh(new_alert)  # Refresh to get the ID
            print(f"SUCCESS: Generated new alert {new_alert.id} for rule {rule_id}")

            # Trigger CTI enrichment as a background task
            await self.cti_service.enrich_alert_with_ip_info(new_alert.id, source_host)
