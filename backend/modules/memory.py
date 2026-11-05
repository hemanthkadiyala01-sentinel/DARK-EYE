from backend.modules.base import BaseModule


class MemoryModule(BaseModule):

    name = "memory"

    def execute(self, message):

        return {
            "module": self.name,
            "response": "Memory module ready.",
            "request": message,
        }