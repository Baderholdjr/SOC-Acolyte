from typing import Dict, Any

class ParsingService:
    """
    Parses raw log data into a structured format based on the log format.
    """

    def parse_log(self, log_format: str, raw_log: str | Dict[str, Any]) -> Dict[str, Any] | None:
        """
        Routes the log to the appropriate parsing function.
        """
        if log_format.lower() == 'json':
            return self._parse_json(raw_log)
        # In the future, other parsers would be added here
        # elif log_format.lower() == 'syslog':
        #     return self._parse_syslog(raw_log)
        else:
            print(f"Warning: No parser available for log format '{log_format}'.")
            return None

    def _parse_json(self, raw_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        For JSON logs, the raw log is already structured. We just return it.
        """
        if isinstance(raw_log, dict):
            return raw_log
        return None

# Create a single instance for the application to use
parsing_service = ParsingService()
