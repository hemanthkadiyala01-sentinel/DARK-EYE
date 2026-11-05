class Conversation:

    def __init__(self):
        self.history = []

    def add_user(self, message):
        self.history.append(
            {
                "role": "user",
                "content": message
            }
        )

    def add_assistant(self, message):
        self.history.append(
            {
                "role": "assistant",
                "content": message
            }
        )

    def clear(self):
        self.history.clear()