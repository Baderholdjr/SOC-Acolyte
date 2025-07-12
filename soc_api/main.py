from fastapi import FastAPI

app = FastAPI(title="Talia SOC Acolyte")

@app.get("/", tags=["Status"])
async def root():
    """
    Root endpoint to confirm the SOC Acolyte is running.
    """
    return {"message": "SOC Acolyte is online."}
