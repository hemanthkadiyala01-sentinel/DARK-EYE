import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    def __init__(self):
        self.app_name = os.getenv("APP_NAME", "DARK EYE")
        self.version = os.getenv("APP_VERSION", "0.1.0")
        self.ollama_host = os.getenv(
            "OLLAMA_HOST",
            "http://127.0.0.1:11434",
        )
        self.model = os.getenv(
            "OLLAMA_MODEL",
            "llama3.2",
        )


settings = Settings()
import os

from dotenv import load_dotenv

load_dotenv()

MODEL_NAME = os.getenv("MODEL_NAME")

OLLAMA_HOST = os.getenv("OLLAMA_HOST")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")