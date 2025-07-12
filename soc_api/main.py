from fastapi import FastAPI, HTTPException
from typing import List
from .core.data_models import LogEntry

app = FastAPI(title="Talia SOC Acolyte")


@app.get("/", tags=["Status"])
async def root():
    """
    Root endpoint to confirm the SOC Acolyte is running.
    """
    return {"message": "SOC Acolyte is online."}


@app.post("/ingest/logs", tags=["Data Ingestion"])
async def ingest_logs(logs: List[LogEntry]):
    """
    Receives a batch of log entries from various sources.

    This is the primary endpoint for data ingestion. For now, it validates
    the data and prints it. In the next step, it will be processed and stored.
    """
    if not logs:
        raise HTTPException(status_code=400, detail="No logs provided in the request.")

    print(f"--- Received batch of {len(logs)} logs ---")
    for log in logs:
        # In a real application, this is where you would send the log
        # to a processing queue (like Kafka or RabbitMQ) or directly
        # to a parsing and storage function.
        print(f"Received log from {log.source_host}: {log.raw_log}")

    return {"status": "success", "logs_received": len(logs)}

