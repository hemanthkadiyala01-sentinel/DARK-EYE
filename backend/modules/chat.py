from backend.modules.base import BaseModule


class ChatModule(BaseModule):

    name = "chat"

    def execute(self, message):

        return {
            "module": self.name,
            "response": "General conversation mode activated."
        }