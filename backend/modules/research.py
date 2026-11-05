from backend.modules.base import BaseModule


class ResearchModule(BaseModule):

    name = "research"

    def execute(self, message):

        return {
            "module": self.name,
            "response": "Research assistant module ready.",
            "request": message,
        }