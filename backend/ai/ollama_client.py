"""
Ollama client for DARK EYE.
"""

import requests

from backend.core.config import settings
from backend.core.logger import get_logger

logger = get_logger()


class OllamaClient:
    def __init__(self):
        self.host = settings.ollama_host
        self.model = settings.model

    def generate(self, prompt: str) -> str:
        url = f"{self.host}/api/generate"

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        try:
            response = requests.post(
                url,
                json=payload,
                timeout=120,
            )

            response.raise_for_status()

            data = response.json()

            return data.get("response", "")

        except Exception as e:
            logger.exception("Ollama Error")

            return f"[ERROR] {e}"