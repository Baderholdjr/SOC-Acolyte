# soc-acolyte/soc_api/core/ueba_service.py
import logging
from sqlalchemy.orm import Session
from sqlalchemy import func
from . import data_models as models
from datetime import datetime, time, timezone
import uuid

class UEBAService:
    """
    A service to perform User and Entity Behavior Analytics.
    """
    NORMAL_HOURS_START = time(8, 0, 0)  # 8:00 AM
    NORMAL_HOURS_END = time(18, 0, 0) # 6:00 PM

    def __init__(self, db: Session):
        self.db = db

    def record_activity(self, event: models.SecurityEvent):
        """
        Records a new user activity event from a security event.
        """
        parsed_data = event.parsed_data
        username = parsed_data.get('user') or parsed_data.get('username')
        action = parsed_data.get('action')

        if not username or not action:
            return # Not an event with user activity

        new_activity = models.UserActivity(
            username=username,
            action=action,
            source_host=event.source_host,
            event_time=event.event_time
        )
        self.db.add(new_activity)
        self.db.commit()
        logging.info(f"Recorded new activity for user '{username}': {action}")

        # After recording, analyze for anomalies
        self.analyze_login_time_anomaly(new_activity)

    def analyze_login_time_anomaly(self, new_activity: models.UserActivity):
        """
        Analyzes a new login activity to see if it's outside the user's
        normal baseline. In this simulation, the baseline is fixed business hours.
        """
        if new_activity.action not in ["login", "login_failed"]:
            return # Only analyze login times for now

        event_time = new_activity.event_time.time()

        # Simple baseline: check if the login is outside normal business hours
        if not (self.NORMAL_HOURS_START <= event_time <= self.NORMAL_HOURS_END):
            logging.warning(f"ANOMALY DETECTED: User '{new_activity.username}' logged in outside normal hours at {event_time}.")
            self._create_ueba_alert(new_activity)

    def _create_ueba_alert(self, activity: models.UserActivity):
        """
        Creates a new alert for a detected UEBA anomaly.
        """
        rule_id = "UEBA-ANOMALY-001"

        # Check if an alert for this specific activity already exists
        existing_alert = self.db.query(models.Alert).filter_by(rule_id=rule_id, event_id=activity.id).first()
        if existing_alert:
            return

        new_alert = models.Alert(
            id=uuid.uuid4(),
            # For UEBA alerts, we can link the event_id to the UserActivity record
            event_id=activity.id,
            rule_id=rule_id,
            severity="HIGH",
            status="NEW"
        )
        self.db.add(new_alert)
        self.db.commit()
        logging.info(f"Successfully generated new UEBA alert for user '{activity.username}'.")

# Create a single instance for the application to use
# Note: A db session will be passed when its methods are called.
ueba_service = UEBAService(db=None)