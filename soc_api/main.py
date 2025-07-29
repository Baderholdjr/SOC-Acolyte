from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from typing import List
from sqlalchemy.orm import Session

from .core import data_models as models
from .core.database import get_db, SessionLocal
from .core.rules_engine import RulesEngine
from .core.parsing_service import parsing_service  # Import the new service

app = FastAPI(title="Talia SOC Acolyte")


async def run_rules_engine_task(host: str):
    db = SessionLocal()
    try:
        engine = RulesEngine()
        await engine.run_engine_for_host(db=db, source_host=host)
    finally:
        db.close()


@app.get("/", tags=["Status"])
async def root():
    return {"message": "SOC Acolyte is online."}


@app.post("/ingest/logs", tags=["Data Ingestion"])
async def ingest_logs(
        logs: List[models.LogEntry],
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    if not logs:
        raise HTTPException(status_code=400, detail="No logs provided in the request.")

    events_created = 0
    unique_hosts = set()
    for log in logs:
        unique_hosts.add(log.source_host)

        # --- NEW: Call the parsing service ---
        parsed_data = parsing_service.parse_log(log.log_format, log.raw_log)
        # --- END NEW ---

        new_event = models.SecurityEvent(
            source_host=log.source_host,
            log_format=log.log_format,
            event_time=log.timestamp,
            raw_log=log.raw_log,
            parsed_data=parsed_data  # Store the parsed data
        )
        db.add(new_event)
        events_created += 1

    db.commit()
    print(f"--- Stored and parsed {events_created} new security events ---")

    if unique_hosts:
        for host in unique_hosts:
            background_tasks.add_task(run_rules_engine_task, host)
        print(f"Queued rules engine tasks for {len(unique_hosts)} hosts.")

    return {"status": "success", "events_stored": events_created}

# ... (rest of the endpoints remain the same)
