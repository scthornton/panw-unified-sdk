"""FastAPI middleware example — async AI security scanning.

Uses FastAPI's native async support for non-blocking security scans.
Ideal for high-throughput AI API services.

Usage:
    pip install fastapi uvicorn
    uvicorn examples.fastapi_middleware:app --reload
"""

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from pan_ai_security import UnifiedClient
from pan_ai_security.exceptions import PanAISecurityError

app = FastAPI(title="AI Chat API with Security Scanning")
security = UnifiedClient()


class ChatRequest(BaseModel):
    prompt: str
    context: str = ""


class ChatResponse(BaseModel):
    response: str
    scan_id: str = ""
    blocked: bool = False


@app.post("/api/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    """AI chat endpoint with integrated security scanning."""

    # Scan the incoming prompt
    try:
        scan_result = await security.scan_async(prompt=req.prompt)
    except PanAISecurityError as e:
        # Log but don't block on scan failures (fail-open policy)
        print(f"Security scan error: {e}")
        scan_result = None

    if scan_result and scan_result.is_blocked:
        threats = [t.threat_type for t in scan_result.threats]
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Request blocked by AI security policy",
                "threats": threats,
                "scan_id": scan_result.scan_id,
            },
        )

    # Your AI model logic here
    ai_response = f"Here's my response to: {req.prompt}"

    return ChatResponse(
        response=ai_response,
        scan_id=scan_result.scan_id if scan_result else "",
    )


@app.post("/api/scan/file")
async def scan_file(request: Request):
    """Scan an uploaded file for malware."""
    body = await request.body()
    filename = request.headers.get("X-Filename", "upload")

    try:
        result = await security.scan_async(file=body, filename=filename)
    except PanAISecurityError as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "verdict": result.verdict.value,
        "category": result.category.value,
        "threats": [t.to_dict() for t in result.threats],
        "scan_id": result.scan_id,
        "duration_ms": result.duration_ms,
    }


@app.on_event("shutdown")
async def shutdown():
    await security.close_async()
