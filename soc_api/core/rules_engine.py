from sqlalchemy.orm import Session
from sqlalchemy import and_, String
from . import data_models as models  # Corrected import
import datetime
import uuid


class RulesEngine:
    """
    Analyzes security events and generates alerts based on predefined rules.
    """

    def __init__(self, db: Session):
        self.db = db

    def run_engine_for_host(self, source_host: str):
        """
        Runs all defined rules for a specific source host.

        Args:
            source_host (str): The source host from the ingested log.
        """
        print(f"Running rules engine for host: {source_host}")
        self._rule_001_multiple_failed_logins(source_host)
        # Future rules would be called here
        # self._rule_002_...(source_host)

    def _rule_001_multiple_failed_logins(self, source_host: str):
        """
        Rule: Detects 5 or more failed logins from the same source host
        within a 5-minute window.
        """
        rule_id = "SOC-RULE-001"
        time_window = datetime.timedelta(minutes=5)
        failure_threshold = 5

        # Find recent failed login events from this host
        # This is a simple text search; a real implementation would use parsed data.
        recent_failed_logins = self.db.query(models.SecurityEvent).filter(
            models.SecurityEvent.source_host == source_host,
            models.SecurityEvent.raw_log.cast(String).ilike('%login_failed%'),
            models.SecurityEvent.event_time >= datetime.datetime.utcnow() - time_window
        ).all()

        if len(recent_failed_logins) >= failure_threshold:
            # Check if an alert for this specific incident already exists
            # by checking against the most recent event.
            latest_event_id = max(event.id for event in recent_failed_logins)

            existing_alert = self.db.query(models.Alert).filter(
                models.Alert.rule_id == rule_id,
                models.Alert.event_id == latest_event_id
            ).first()

            if existing_alert:
                print(f"Alert for rule {rule_id} and host {source_host} already exists. Skipping.")
                return

            # Create a new Alert
            new_alert = models.Alert(
                id=uuid.uuid4(),
                event_id=latest_event_id,
                rule_id=rule_id,
                severity="MEDIUM",
                status="NEW"
            )
            self.db.add(new_alert)
            self.db.commit()
            print(f"SUCCESS: Generated new alert for rule {rule_id} for host {source_host}")
