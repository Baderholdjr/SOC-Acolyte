from fastapi import FastAPI, HTTPException, Depends
from typing import List
from sqlalchemy.orm import Session

from .core.data_models import LogEntry
from .core import data_models as models  # Corrected import
from .core.database import get_db

app = FastAPI(title="Talia SOC Acolyte")


@app.get("/", tags=["Status"])
async def root():
    """
    Root endpoint to confirm the SOC Acolyte is running.
    """
    return {"message": "SOC Acolyte is online."}


@app.post("/ingest/logs", tags=["Data Ingestion"])
async def ingest_logs(logs: List[LogEntry], db: Session = Depends(get_db)):
    """
    Receives a batch of log entries, converts them to SecurityEvent objects,
    and stores them in the database.
    """
    if not logs:
        raise HTTPException(status_code=400, detail="No logs provided in the request.")

    events_created = 0
    for log in logs:
        # Here, we convert the incoming LogEntry into a SecurityEvent DB model
        new_event = models.SecurityEvent(
            source_host=log.source_host,
            log_format=log.log_format,
            event_time=log.timestamp,
            raw_log=log.raw_log
        )
        db.add(new_event)
        events_created += 1

    db.commit()

    print(f"--- Stored {events_created} new security events in the database ---")

    return {"status": "success", "events_stored": events_created}
