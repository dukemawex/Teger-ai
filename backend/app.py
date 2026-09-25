import base64
import hashlib
import hmac
import os
import time
import uuid
from collections import defaultdict, deque

from dotenv import load_dotenv

# Load environment before importing modules that depend on it.
load_dotenv()

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from analyzer import AnalysisResult, analyze_message  # noqa: E402

app = FastAPI(title="Teger AI Backend", version="0.2.0")

origins = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

APP_SECRET = os.getenv("APP_SECRET", "")
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "10"))
_rate_windows: dict[str, deque[float]] = defaultdict(deque)


class InstallationResponse(BaseModel):
    installation_id: str
    token: str


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=20000)
    context: str = Field(default="", max_length=1000)


def _require_secret() -> bytes:
    if not APP_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server installation authentication is not configured.",
        )
    return APP_SECRET.encode("utf-8")


def _sign_installation(installation_id: str) -> str:
    signature = hmac.new(_require_secret(), installation_id.encode("utf-8"), hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{installation_id}.{encoded}"


def _verify_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing installation token.")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        installation_id, signature = token.split(".", 1)
        uuid.UUID(installation_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid installation token.") from None

    expected = _sign_installation(installation_id)
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid installation token.")
    return installation_id


def _enforce_rate_limit(key: str) -> None:
    now = time.monotonic()
    window = _rate_windows[key]
    while window and now - window[0] >= 60:
        window.popleft()
    if len(window) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Scan limit reached. Try again shortly.")
    window.append(now)


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.2.0"}


@app.post("/installations", response_model=InstallationResponse)
def create_installation():
    installation_id = str(uuid.uuid4())
    return InstallationResponse(installation_id=installation_id, token=_sign_installation(installation_id))


@app.post("/analyze", response_model=AnalysisResult)
def analyze(
    req: AnalyzeRequest,
    request: Request,
    installation_id: str = Depends(_verify_token),
):
    client_key = f"{installation_id}:{request.client.host if request.client else 'unknown'}"
    _enforce_rate_limit(client_key)

    try:
        return analyze_message(req.content.strip(), req.context.strip())
    except HTTPException:
        raise
    except Exception:
        # Do not leak provider errors, prompts, credentials, or message content.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Analysis service is temporarily unavailable.",
        ) from None
