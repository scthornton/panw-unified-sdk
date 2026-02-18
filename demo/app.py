"""Interactive chat demo with pan-ai-security as the security layer.

User sends messages (+ optional files) through a chat interface.
The SDK scans everything before it reaches the LLM. If the scan passes,
the prompt goes to Groq. If blocked, the LLM never sees it.

Run with:
    python -m uvicorn demo.app:app --reload --port 8080
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from pan_ai_security import UnifiedClient
from pan_ai_security.exceptions import ConfigurationError, PanAISecurityError

logger = logging.getLogger("demo")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="pan-ai-security Demo", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global fallback — always return JSON, never plain text error pages.
@app.exception_handler(Exception)
async def _global_exc_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "error_type": "internal",
        },
    )


# ---------------------------------------------------------------------------
# Thread pool for SDK calls (avoids event-loop conflicts with aiohttp)
# ---------------------------------------------------------------------------

_executor = ThreadPoolExecutor(max_workers=4)


def _scan_text_sync(client: UnifiedClient, prompt: str) -> dict:
    """Run a text scan in a worker thread — no event-loop nesting."""
    start = time.perf_counter()
    result = client.scan(prompt=prompt)
    elapsed = int((time.perf_counter() - start) * 1000)
    data = result.to_dict()
    data["duration_ms"] = elapsed
    return data


def _scan_file_sync(client: UnifiedClient, file_bytes: bytes, filename: str) -> dict:
    """Run a file scan in a worker thread — no event-loop nesting."""
    start = time.perf_counter()
    result = client.scan(file=file_bytes, filename=filename)
    elapsed = int((time.perf_counter() - start) * 1000)
    data = result.to_dict()
    data["duration_ms"] = elapsed
    return data


# ---------------------------------------------------------------------------
# Security client — lazy init
# ---------------------------------------------------------------------------

_client: UnifiedClient | None = None
_init_error: str | None = None


def _get_client() -> UnifiedClient:
    global _client, _init_error
    if _client is None and _init_error is None:
        try:
            _client = UnifiedClient()
        except (ConfigurationError, PanAISecurityError) as exc:
            _init_error = str(exc)
            logger.warning("Security client init failed: %s", _init_error)
        except Exception as exc:
            _init_error = f"Unexpected error: {exc}"
            logger.exception("Security client init failed")
    if _client is None:
        raise ConfigurationError(_init_error or "Client not initialized")
    return _client


# ---------------------------------------------------------------------------
# LLM client — Groq
# ---------------------------------------------------------------------------

_groq_client = None
_groq_error: str | None = None

GROQ_MODEL = "llama-3.3-70b-versatile"
SYSTEM_PROMPT = (
    "You are a helpful AI assistant. Answer questions clearly and concisely. "
    "You are part of a demo showcasing Palo Alto Networks AI security scanning — "
    "every message the user sends is scanned for threats before reaching you."
)


def _get_groq():
    global _groq_client, _groq_error
    if _groq_client is None and _groq_error is None:
        api_key = os.getenv("GROQ_API_KEY", "")
        if not api_key:
            _groq_error = "GROQ_API_KEY not set"
            return None
        try:
            from groq import Groq
            _groq_client = Groq(api_key=api_key)
        except ImportError:
            _groq_error = "groq package not installed (pip install groq)"
        except Exception as exc:
            _groq_error = str(exc)
    return _groq_client


def _chat_with_llm(prompt: str, filename: str | None = None) -> dict:
    """Send a prompt to Groq and return the response."""
    client = _get_groq()
    if client is None:
        return {"error": _groq_error, "reply": None}

    # Build user message with file context
    user_content = prompt
    if filename:
        user_content += f"\n\n[The user also attached a file: {filename}]"

    try:
        start = time.perf_counter()
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            temperature=0.7,
            max_tokens=1024,
        )
        elapsed = int((time.perf_counter() - start) * 1000)
        return {
            "reply": completion.choices[0].message.content,
            "model": GROQ_MODEL,
            "llm_duration_ms": elapsed,
            "error": None,
        }
    except Exception as exc:
        return {"error": str(exc), "reply": None}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the chat frontend."""
    html_path = Path(__file__).parent / "index.html"
    return HTMLResponse(html_path.read_text())


@app.get("/api/health")
async def health():
    """Show which services are configured."""
    try:
        client = _get_client()
        cfg = client._config
        airs_ok = cfg.has_airs
        wf_ok = cfg.has_wildfire
    except (ConfigurationError, PanAISecurityError):
        airs_ok = False
        wf_ok = False

    groq_ok = bool(os.getenv("GROQ_API_KEY"))
    return {
        "airs": airs_ok,
        "wildfire": wf_ok,
        "groq": groq_ok,
        "groq_model": GROQ_MODEL if groq_ok else None,
    }


@app.post("/api/send")
async def send_message(
    prompt: str = Form(""),
    file: UploadFile | None = File(None),
):
    """Process a chat message through the security pipeline.

    Flow: scan prompt (AIRS) + scan file (WildFire) -> if safe -> LLM -> response
    """
    loop = asyncio.get_event_loop()

    result: dict = {
        "prompt": prompt,
        "filename": None,
        "file_size": None,
        "scans": [],
        "overall_verdict": "allow",
        "blocked": False,
        "llm": None,
    }

    file_bytes: bytes | None = None
    if file and file.filename:
        file_bytes = await file.read()
        result["filename"] = file.filename
        result["file_size"] = len(file_bytes)

    # --- Security scanning (run in thread pool to avoid event-loop nesting) ---
    try:
        client = _get_client()

        # Scan text via AIRS
        if prompt.strip():
            try:
                scan_data = await loop.run_in_executor(
                    _executor, _scan_text_sync, client, prompt
                )
                scan_data["scan_type"] = "text"
                scan_data["label"] = "Prompt \u2192 AIRS"
                result["scans"].append(scan_data)
                if scan_data.get("verdict") == "block":
                    result["overall_verdict"] = "block"
                    result["blocked"] = True
            except Exception as exc:
                logger.exception("Text scan failed")
                result["scans"].append({
                    "scan_type": "text",
                    "label": "Prompt \u2192 AIRS",
                    "error": str(exc),
                })

        # Scan file via WildFire
        if file_bytes:
            try:
                scan_data = await loop.run_in_executor(
                    _executor, _scan_file_sync, client, file_bytes, result["filename"]
                )
                scan_data["scan_type"] = "file"
                scan_data["label"] = f"{result['filename']} \u2192 WildFire"
                result["scans"].append(scan_data)
                if scan_data.get("verdict") == "block":
                    result["overall_verdict"] = "block"
                    result["blocked"] = True
            except Exception as exc:
                logger.exception("File scan failed")
                result["scans"].append({
                    "scan_type": "file",
                    "label": f"{result['filename']} \u2192 WildFire",
                    "error": str(exc),
                })

    except ConfigurationError as exc:
        return JSONResponse(
            status_code=422,
            content={"error": str(exc), "error_type": "configuration"},
        )

    # --- LLM (only if security passed and there's a prompt) ---
    if not result["blocked"] and prompt.strip():
        result["llm"] = await loop.run_in_executor(
            _executor, _chat_with_llm, prompt, result["filename"]
        )

    return result
