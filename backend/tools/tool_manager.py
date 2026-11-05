class ToolManager:

    def __init__(self):
        self.tools = {}

    def register(self, name, tool):
        self.tools[name] = tool

    def execute(self, name, *args, **kwargs):

        if name not in self.tools:
            return {
                "success": False,
                "message": f"Tool '{name}' not found."
            }

        return self.tools[name](*args, **kwargs)