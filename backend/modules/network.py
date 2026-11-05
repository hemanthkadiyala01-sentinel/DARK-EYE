from backend.modules.base import BaseModule


class NetworkModule(BaseModule):

    name = "network"

    def execute(self, message):

        return {
            "module": self.name,
            "response": "Network diagnostics module selected.",
            "request": message,
        }