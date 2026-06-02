from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.pipeline import LLMGuardPipeline

app = FastAPI(title="LLM-Guard-Scanner API")
pipeline = LLMGuardPipeline()


class ScanRequest(BaseModel):
    prompt: str
    enable_ml: bool = False


class ScanResponse(BaseModel):
    is_secure: bool
    risk_score: float
    findings: List[str]
    is_injection: bool
    pii_found: bool


@app.post("/scan", response_model=ScanResponse)
async def scan_prompt(request: ScanRequest):
    try:
        result = pipeline.scan_input(request.prompt)
        return ScanResponse(
            is_secure=not result.is_blocked,
            risk_score=result.risk_score,
            findings=result.findings,
            is_injection=result.is_injection,
            pii_found=result.pii_found,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
