import httpx
from sqlalchemy.orm import Session
from . import data_models as models # Corrected import
import uuid

class CTIService:
    """
    Enriches alerts by querying external Cyber Threat Intelligence providers.
    """
    # In a real application, this API key would be stored securely (e.g., environment variable)
    ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"
    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, db: Session):
        self.db = db

    async def enrich_alert_with_ip_info(self, alert_id: uuid.UUID, ip_address: str):
        """
        Queries AbuseIPDB for information about an IP address and updates the alert.
        """
        print(f"Starting CTI enrichment for IP: {ip_address} on alert: {alert_id}")

        headers = {
            'Accept': 'application/json',
            'Key': self.ABUSEIPDB_API_KEY
        }
        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'
        }

        try:
            async with httpx.AsyncClient() as client:
                # In a real app, you would make the actual call.
                # For this test, we will simulate the response to avoid needing a real API key.
                # response = await client.get(self.BASE_URL, headers=headers, params=querystring)
                # response.raise_for_status()
                # enrichment_data = response.json()

                # --- SIMULATED RESPONSE ---
                print("SIMULATING CTI API CALL...")
                enrichment_data = {
                    "data": {
                        "ipAddress": ip_address,
                        "isPublic": True,
                        "abuseConfidenceScore": 85,
                        "countryCode": "CN",
                        "usageType": "Data Center/Web Hosting/Transit",
                        "isp": "Tencent Cloud",
                        "domain": "tencent.com",
                        "totalReports": 150,
                        "lastReportedAt": "2025-07-10T19:38:55+00:00"
                    }
                }
                # --- END SIMULATION ---

            # Find the alert in the database
            alert_to_update = self.db.query(models.Alert).filter(models.Alert.id == alert_id).first()
            if alert_to_update:
                alert_to_update.enrichment_data = enrichment_data
                self.db.commit()
                print(f"SUCCESS: Successfully enriched alert {alert_id} with CTI data.")
            else:
                print(f"ERROR: Could not find alert {alert_id} to enrich.")

        except httpx.HTTPStatusError as e:
            print(f"Error querying AbuseIPDB API: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            print(f"An unexpected error occurred during CTI enrichment: {e}")
