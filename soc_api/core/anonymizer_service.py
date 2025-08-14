import hashlib
from . import data_models as models
from . import response_actions as response_models
from typing import Any, Dict


class AnonymizerService:
    """
    Anonymizes alert and event data before it's sent to the Master AI.
    """
    # --- ADDED: Define a list of sensitive keys to look for in logs ---
    SENSITIVE_KEYS = ['user', 'username', 'password', 'email', 'firstname', 'lastname', 'ip_address']

    def _hash_identifier(self, identifier: str) -> str:
        """
        Creates a SHA256 hash of an identifier to anonymize it.
        """
        return hashlib.sha256(identifier.encode()).hexdigest()

    # --- REFINED: New scrubbing logic ---
    def _scrub_raw_data(self, data: Any) -> Any:
        """
        Recursively scrubs a dictionary or list for sensitive information.
        It checks each key against the SENSITIVE_KEYS list and redacts the value if it matches.
        """
        if isinstance(data, dict):
            scrubbed_dict = {}
            for key, value in data.items():
                # If the key (case-insensitive) is in our sensitive list, redact the value
                if key.lower() in self.SENSITIVE_KEYS:
                    scrubbed_dict[key] = "[REDACTED]"
                else:
                    # Otherwise, continue scrubbing recursively
                    scrubbed_dict[key] = self._scrub_raw_data(value)
            return scrubbed_dict
        elif isinstance(data, list):
            # If the data is a list, apply scrubbing to each item
            return [self._scrub_raw_data(item) for item in data]
        else:
            # Return the value as is if it's not a dict or list
            return data

    def anonymize_alert(self, alert: models.Alert, event: models.SecurityEvent) -> models.AnonymizedAlertPayload:
        """
        Takes an Alert and its source SecurityEvent and creates an
        anonymized payload suitable for submission to the Master AI.
        """
        print(f"Anonymizing alert {alert.id}...")

        # The asset ID is still created by hashing the source host
        anonymized_id = self._hash_identifier(event.source_host)

        # The raw log is now passed to our new, more robust scrubbing function
        scrubbed_log = self._scrub_raw_data(event.raw_log)

        payload = models.AnonymizedAlertPayload(
            anonymized_asset_id=anonymized_id,
            alert_type=alert.rule_id,
            severity=alert.severity,
            event_time=event.event_time,
            raw_data=scrubbed_log
        )

        print(f"Successfully created anonymized payload for alert {alert.id}.")
        return payload

        # --- ADDED: Method to anonymize response actions ---

    def anonymize_action(self, action: response_models.ResponseAction,
                         event: models.SecurityEvent) -> models.AnonymizedResponseActionPayload:
        """
        Takes a ResponseAction and its source SecurityEvent and creates an
        anonymized payload suitable for submission to the Master AI.
        """
        print(f"Anonymizing response action {action.id}...")

        anonymized_id = self._hash_identifier(event.source_host)

        # Find the execution log for this action to get the result
        execution_log = action.executions[0] if action.executions else None

        payload = models.AnonymizedResponseActionPayload(
            anonymized_asset_id=anonymized_id,
            alert_type=action.alert.rule_id,
            action_type=action.action_type,
            executed_at=action.executed_at,
            status=execution_log.status if execution_log else "UNKNOWN",
            result=execution_log.result if execution_log else {"error": "No execution log found"}
        )

        print(f"Successfully created anonymized payload for action {action.id}.")
        return payload
