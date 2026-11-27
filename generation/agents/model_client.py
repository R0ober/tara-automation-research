import os
from urllib.parse import urlsplit


def read_model_settings():
    base_url = os.environ.get("OPENAI_BASE_URL", "").strip().rstrip("/")
    model = os.environ.get("OPENAI_MODEL", "").strip()
    if not base_url:
        raise ValueError("Set OPENAI_BASE_URL to the model server API URL.")
    url = urlsplit(base_url)
    if url.scheme not in ("http", "https") or not url.hostname:
        raise ValueError("OPENAI_BASE_URL must be an HTTP or HTTPS URL with a host.")
    if not model:
        raise ValueError("Set OPENAI_MODEL to the model name served at OPENAI_BASE_URL.")
    return base_url, model


def create_client(base_url):
    from openai import OpenAI

    # The SDK requires a key even for servers that run without authentication.
    return OpenAI(base_url=base_url, api_key=os.environ.get("OPENAI_API_KEY") or "unused")
