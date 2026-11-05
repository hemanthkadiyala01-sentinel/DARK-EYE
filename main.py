from backend.ai.chat_manager import ChatManager
from backend.core.logger import get_logger
from backend.core.config import settings

logger = get_logger()

chat = ChatManager()

logger.info("=" * 50)
logger.info("Starting %s", settings.app_name)
logger.info("Version : %s", settings.version)

while True:
    user = input("\nYou: ")

    if user.lower() in ["exit", "quit"]:
        break

    reply = chat.chat(user)

    print(f"\nDARK EYE:\n{reply}")