from backend.ai.dispatcher import Dispatcher
from backend.ai.module_loader import ModuleLoader


class Brain:

    def __init__(self):
        self.dispatcher = Dispatcher()
        self.loader = ModuleLoader()

    def think(self, message):
        module_name = self.dispatcher.route(message)
        module = self.loader.load(module_name)
        return module.execute(message)