from backend.ai.prompts import build_prompt
from backend.ai.ollama_client import OllamaClient
from backend.ai.conversation import Conversation
from backend.ai.dispatcher import Dispatcher


class ChatManager:

    def __init__(self):
        self.conversation = Conversation()
        self.client = OllamaClient()
        self.dispatcher = Dispatcher()


    def chat(self, user_message: str):

        module = self.dispatcher.route(user_message)

        self.conversation.add_user(user_message)

        prompt = build_prompt(
            self.conversation.history
        )

        prompt = f"""
You are DARK EYE.

Current module:
{module}

User request:
{user_message}

Conversation:
{prompt}
"""

        answer = self.client.generate(prompt)

        self.conversation.add_assistant(answer)

        return answer