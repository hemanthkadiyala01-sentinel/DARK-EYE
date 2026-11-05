import importlib


class ModuleLoader:

    def load(self, module_name):

        module = importlib.import_module(
            f"backend.modules.{module_name}"
        )

        class_name = module_name.capitalize() + "Module"

        module_class = getattr(module, class_name)

        return module_class()