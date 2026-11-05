class DarkEyeError(Exception):
    """Base exception for DARK EYE."""


class OllamaConnectionError(DarkEyeError):
    """Raised when Ollama is unavailable."""


class ConfigurationError(DarkEyeError):
    """Configuration-related error."""


class ModelConnectionError(DarkEyeError):
    """Raised when the LLM cannot be reached."""


class MemoryError(DarkEyeError):
    """Memory subsystem error."""


class PluginError(DarkEyeError):
    """Plugin subsystem error."""