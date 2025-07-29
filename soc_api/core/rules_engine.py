import os
import yaml
from sqlalchemy.orm import Session
from sqlalchemy import and_, String
from . import data_models as models
from .cti_service import CTIService
from datetime import datetime, timedelta, timezone  # Import timezone
import uuid


class RulesEngine:
    """
    Analyzes security events by dynamically loading and processing rules from YAML files.
    """
    RULES_DIR = "rules"

    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self) -> list:
        loaded_rules = []
        try:
            for filename in os.listdir(self.RULES_DIR):
                if filename.endswith(".yml"):
                    file_path = os.path.join(self.RULES_DIR, filename)
                    with open(file_path, 'r') as f:
                        rule = yaml.safe_load(f)
                        if rule.get('enabled', False):
                            loaded_rules.append(rule)
            print(f"Successfully loaded {len(loaded_rules)} enabled rules.")
        except FileNotFoundError:
            print(f"ERROR: Rules directory '{self.RULES_DIR}' not found.")
        return loaded_rules

    async def run_engine_for_host(self, db: Session, source_host: str):
        print(f"Running rules engine for host: {source_host}")
        for rule in self.rules:
            await self._evaluate_rule(db, rule, source_host)

    async def _evaluate_rule(self, db: Session, rule: dict, source_host: str):
        trigger_config = rule.get('trigger', {})

        # --- FIX: Corrected Time Window Logic ---
        # 1. Build filters without the time component first
        base_filters = []
        for condition in rule.get('conditions', {}).get('all', []):
            field, operator, value = condition['field'], condition['operator'], condition['value']
            if field == "security_events.source_host" and operator == "equals":
                base_filters.append(models.SecurityEvent.source_host == source_host)
            elif field == "security_events.parsed_data.action" and operator == "equals":
                base_filters.append(models.SecurityEvent.parsed_data['action'].as_string() == str(value))

        # 2. Find all potentially relevant events, ordered by most recent
        all_matching_events = db.query(models.SecurityEvent).filter(and_(*base_filters)).order_by(
            models.SecurityEvent.event_time.desc()).all()

        # 3. If we don't have enough events to possibly meet the threshold, stop early.
        threshold = trigger_config.get('value', 5)
        if len(all_matching_events) < threshold:
            return

        # 4. Calculate the time window based on the timestamp of the MOST RECENT event
        latest_event_time = all_matching_events[0].event_time
        time_window = timedelta(minutes=trigger_config.get('time_window_minutes', 5))
        time_window_start = latest_event_time - time_window

        # 5. Now, filter the events that fall within this correct time window
        events_in_window = [event for event in all_matching_events if event.event_time >= time_window_start]

        # 6. Check if the count in the window meets the threshold
        if len(events_in_window) >= threshold:
            await self._create_alert_if_new(db, rule, events_in_window)
        # --- END FIX ---

    async def _create_alert_if_new(self, db: Session, rule: dict, events: list):
        rule_id = rule['id']
        latest_event = max(events, key=lambda e: e.event_time)

        existing_alert = db.query(models.Alert).filter(
            models.Alert.rule_id == rule_id,
            models.Alert.event_id == latest_event.id
        ).first()

        if existing_alert:
            return

        new_alert = models.Alert(
            id=uuid.uuid4(),
            event_id=latest_event.id,
            rule_id=rule_id,
            severity=rule.get('severity', 'UNKNOWN'),
            status="NEW"
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        print(f"SUCCESS: Generated new alert for rule {rule_id}")

        cti_service = CTIService(db)
        source_host_for_enrichment = events[0].source_host if events else None
        if source_host_for_enrichment:
            await cti_service.enrich_alert_with_ip_info(new_alert.id, source_host_for_enrichment)
