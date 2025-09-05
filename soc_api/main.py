# baderholdjr/soc-acolyte/Baderholdjr-SOC-Acolyte-972c4a372878ed1d90928f44cb32f2997389fb00/soc_api/main.py
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from typing import List, Optional
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func
from uuid import UUID

from .core import data_models as models
from .core import response_actions
from .core.database import get_db, SessionLocal
from .core.rules_engine import RulesEngine
from .core.anonymizer_service import AnonymizerService
from .core.cti_service import CTIService
from .core.response_action_service import ResponseActionService
from .core.nlp_service import nlp_service
app = FastAPI(title="Talia SOC Acolyte")


# Helper function for background tasks to ensure a fresh DB session
async def run_rules_engine_task(host: str):
    db = SessionLocal()
    try:
        engine = RulesEngine()
        await engine.run_engine_for_host(db=db, source_host=host)
    finally:
        db.close()


async def run_response_action_task(action_id: UUID):
    db = SessionLocal()
    try:
        service = ResponseActionService(db)
        await service.execute_action(action_id)
    finally:
        db.close()


# --- API Endpoints ---

@app.get("/", tags=["Status"])
async def root():
    """
    Root endpoint to confirm the SOC Acolyte is running.
    """
    return {"message": "SOC Acolyte is online."}


@app.post("/ingest/logs", tags=["Data Ingestion"])
async def ingest_logs(
        logs: List[models.LogEntry],
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    """
    Receives a batch of log entries, parses them (using NLP for unstructured logs),
    stores them, and triggers the rules engine to analyze them in the background.
    """
    if not logs:
        raise HTTPException(status_code=400, detail="No logs provided.")

    events_created = 0
    unique_hosts = set()
    for log in logs:
        unique_hosts.add(log.source_host)

        # --- UPDATED PARSING LOGIC ---
        parsed_data = {}
        if isinstance(log.raw_log, dict):
            # If log is already structured, use it directly
            parsed_data = log.raw_log
        elif isinstance(log.raw_log, str):
            # If log is a string, use the new NLP service to parse it
            parsed_data = await nlp_service.parse_unstructured_log(log.raw_log)
        # --- END UPDATE ---

        new_event = models.SecurityEvent(
            source_host=log.source_host,
            log_format=log.log_format,
            event_time=log.timestamp,
            raw_log=log.raw_log,
            parsed_data=parsed_data
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


@app.get("/alerts", tags=["Alerts"], response_model=List[models.AlertResponse])
async def get_alerts(status: Optional[str] = None, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieves a list of alerts from the database.
    Can optionally filter by status (e.g., 'NEW', 'INVESTIGATING', 'CLOSED').
    """
    query = db.query(models.Alert)

    if status:
        query = query.filter(models.Alert.status == status.upper())

    alerts = query.order_by(models.Alert.created_at.desc()).limit(limit).all()

    return alerts


@app.patch("/alerts/{alert_id}/status", tags=["Alerts"], response_model=models.AlertResponse)
async def update_alert_status(
        alert_id: UUID,
        status_update: models.AlertStatusUpdateRequest,
        db: Session = Depends(get_db)
):
    """
    Updates the status of a specific alert.
    """
    alert_to_update = db.query(models.Alert).filter(models.Alert.id == alert_id).first()

    if not alert_to_update:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert_to_update.status = status_update.status
    db.commit()
    db.refresh(alert_to_update)

    print(f"Updated status for alert {alert_id} to {status_update.status}")

    return alert_to_update


@app.post("/alerts/{alert_id}/actions", tags=["Response Actions"], response_model=models.ResponseActionResponse)
async def trigger_response_action(
        alert_id: UUID,
        action_request: models.ResponseActionCreateRequest,
        background_tasks: BackgroundTasks,
        db: Session = Depends(get_db)
):
    """
    Creates and triggers a response action for a given alert. The action itself
    is executed in the background.
    """
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    new_action = response_actions.ResponseAction(
        alert_id=alert_id,
        action_type=action_request.action_type,
        parameters=action_request.parameters
    )
    db.add(new_action)
    db.commit()
    db.refresh(new_action)

    background_tasks.add_task(run_response_action_task, new_action.id)
    print(f"Queued response action '{new_action.action_type}' for alert '{alert_id}'")

    return new_action


@app.get("/alerts/summary", tags=["Alerts"], response_model=models.AlertSummaryResponse)
async def get_alert_summary(db: Session = Depends(get_db)):
    """
    Returns a summary of alert counts.
    """
    total_alerts = db.query(func.count(models.Alert.id)).scalar()
    new_alerts = db.query(func.count(models.Alert.id)).filter(models.Alert.status == 'NEW').scalar()

    severity_counts = db.query(
        models.Alert.severity, func.count(models.Alert.id)
    ).group_by(models.Alert.severity).all()

    by_severity = {severity: count for severity, count in severity_counts}

    return models.AlertSummaryResponse(
        total_alerts=total_alerts,
        new_alerts=new_alerts,
        by_severity=by_severity
    )


@app.get("/inquisitor/fetch-data", tags=["Inquisitor Interface"], response_model=models.InquisitorDataPackage)
async def fetch_data_for_inquisitor(db: Session = Depends(get_db)):
    """
    Gathers all new/closed alerts AND completed response actions, anonymizes them,
    and packages them for the Inquisitor to pick up.
    """
    anonymizer = AnonymizerService()

    anonymized_alerts = []
    anonymized_actions = []

    alerts_to_report = db.query(models.Alert).filter(
        models.Alert.status.in_(['NEW', 'CLOSED'])
    ).all()

    for alert in alerts_to_report:
        event = db.query(models.SecurityEvent).filter(models.SecurityEvent.id == alert.event_id).first()
        if event:
            payload = anonymizer.anonymize_alert(alert, event)
            anonymized_alerts.append(payload)

    actions_to_report = db.query(response_actions.ResponseAction).options(
        joinedload(response_actions.ResponseAction.alert),
        joinedload(response_actions.ResponseAction.executions)
    ).filter(
        response_actions.ResponseAction.status == 'COMPLETED'
    ).all()

    for action in actions_to_report:
        if action.alert:
            event = db.query(models.SecurityEvent).filter(models.SecurityEvent.id == action.alert.event_id).first()
            if event:
                payload = anonymizer.anonymize_action(action, event)
                anonymized_actions.append(payload)

    return models.InquisitorDataPackage(
        alerts=anonymized_alerts,
        response_actions=anonymized_actions
    )
