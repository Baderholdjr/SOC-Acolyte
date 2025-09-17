# talia_project/soc_acolyte/soc_api/core/cti_service.py
import os
from typing import Dict, Any
import virustotal_api

class CTIService:
    """
    A service for enriching security alerts with Cyber Threat Intelligence (CTI)
    from external sources like VirusTotal.
    """

    def __init__(self):
        self.virustotal = virustotal_api.VirusTotal(os.environ.get("VIRUSTOTAL_API_KEY"))

    def enrich_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriches an alert with CTI data.

        For now, this focuses on IP address reputation, but it can be
        expanded to include domain names, file hashes, etc.
        """
        if "source_ip" in alert_data:
            ip_address = alert_data["source_ip"]
            ip_reputation = self._get_ip_reputation(ip_address)
            if ip_reputation:
                alert_data["cti_enrichment"] = {
                    "source_ip_reputation": ip_reputation
                }
        return alert_data

    def _get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """
        Retrieves the reputation of an IP address from VirusTotal.
        """
        try:
            response = self.virustotal.ip_address(ip_address)
            return response.json()
        except Exception as e:
            print(f"Error querying VirusTotal for IP {ip_address}: {e}")
            return None