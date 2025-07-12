import os
import yaml
from sqlalchemy.orm import Session
from sqlalchemy import and_, String
from . import data_models as models
from .cti_service import CTIService
import datetime
import uuid

class RulesEngine:
    """
    Analyzes security events by dynamically loading and processing rules from YAML files.
    """
    RULES_DIR = "rules"

    def __init__(self):
        """The constructor no longer takes a database session."""
        self.rules = self._load_rules()

    def _load_rules(self) -> list:
        """Loads all enabled .yml rule files from the rules directory."""
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
        """
        Runs all loaded rules for a specific source host.
        Requires a database session to be passed in.
        """
        print(f"Running rules engine for host: {source_host}")
        for rule in self.rules:
            await self._evaluate_rule(db, rule, source_host)

    async def _evaluate_rule(self, db: Session, rule: dict, source_host: str):
        """
        Dynamically builds and executes a query based on the rule's conditions.
        """
        trigger_config = rule.get('trigger', {})
        time_window = datetime.timedelta(minutes=trigger_config.get('time_window_minutes', 5))
        time_window_start = datetime.datetime.utcnow() - time_window

        filters = []
        for condition in rule.get('conditions', {}).get('all', []):
            field, operator, value = condition['field'], condition['operator'], condition['value']
            if value == "{source_host}": value = source_host
            if value == "{time_window_start}": value = time_window_start

            if field == "security_events.source_host" and operator == "equals":
                filters.append(models.SecurityEvent.source_host == value)
            elif field == "security_events.raw_log" and operator == "contains":
                filters.append(models.SecurityEvent.raw_log.cast(String).ilike(f'%{value}%'))
            elif field == "security_events.event_time" and operator == "greater_than_or_equal_to":
                filters.append(models.SecurityEvent.event_time >= value)

        matching_events = db.query(models.SecurityEvent).filter(and_(*filters)).all()

        if trigger_config.get('operator') == 'greater_than_or_equal_to':
            if len(matching_events) >= trigger_config.get('value', 1):
                await self._create_alert_if_new(db, rule, matching_events)

    async def _create_alert_if_new(self, db: Session, rule: dict, events: list):
        """Creates a new alert if one doesn't already exist for this incident."""
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
