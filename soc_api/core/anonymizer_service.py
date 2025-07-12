import hashlib
from . import data_models as models


class AnonymizerService:
    """
    Anonymizes alert and event data before it's sent to the Master AI.
    """

    def _hash_identifier(self, identifier: str) -> str:
        """
        Creates a SHA256 hash of an identifier to anonymize it.
        """
        return hashlib.sha256(identifier.encode()).hexdigest()

    def _scrub_raw_data(self, raw_data: dict) -> dict:
        """
        Placeholder for a more advanced PII scrubbing function.
        """
        scrubbed_data = raw_data.copy()
        print("NOTE: Skipping advanced PII scrubbing for this version.")
        return scrubbed_data

    def anonymize_alert(self, alert: models.Alert, event: models.SecurityEvent) -> models.AnonymizedAlertPayload:
        """
        Takes an Alert and its source SecurityEvent and creates an
        anonymized payload suitable for submission to the Master AI.
        """
        print(f"Anonymizing alert {alert.id}...")

        anonymized_id = self._hash_identifier(event.source_host)
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
