"""ASGI entry point: ``uvicorn teger_api.main:app``."""
from .app import create_app

app = create_app()
