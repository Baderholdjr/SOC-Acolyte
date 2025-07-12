from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from typing import List
from sqlalchemy.orm import Session

from .core.data_models import LogEntry
from .core import data_models as models
from .core.database import get_db
from .core.rules_engine import RulesEngine  # Import the new engine

app = FastAPI(title="Talia SOC Acolyte")


@app.get("/", tags=["Status"])
async def root():
    """
    Root endpoint to confirm the SOC Acolyte is running.
    """
    return {"message": "SOC Acolyte is online."}


@app.post("/ingest/logs", tags=["Data Ingestion"])
async def ingest_logs(
        logs: List[LogEntry],
        background_tasks: BackgroundTasks,  # Add dependency
        db: Session = Depends(get_db)
):
    """
    Receives a batch of log entries, stores them, and triggers the
    rules engine to analyze them in the background.
    """
    if not logs:
        raise HTTPException(status_code=400, detail="No logs provided in the request.")

    events_created = 0
    unique_hosts = set()
    for log in logs:
        unique_hosts.add(log.source_host)
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

    # Trigger rules engine for each unique host in the background
    if unique_hosts:
        engine = RulesEngine(db)
        for host in unique_hosts:
            background_tasks.add_task(engine.run_engine_for_host, host)
        print(f"Queued rules engine tasks for {len(unique_hosts)} hosts.")

    return {"status": "success", "events_stored": events_created}
