from backend.modules.base import BaseModule
from backend.services.system_service import SystemService


class SystemModule(BaseModule):

    name = "system"

    def __init__(self):
        self.system = SystemService()

    def execute(self, message):

        text = message.lower()

        if "cpu" in text:
            return {
                "module": self.name,
                "cpu": self.system.cpu()
            }

        if "ram" in text or "memory" in text:
            ram = self.system.ram()

            return {
                "module": self.name,
                "used": round(ram.used / (1024**3), 2),
                "total": round(ram.total / (1024**3), 2),
                "percent": ram.percent
            }

        if "disk" in text:

            disk = self.system.disk()

            return {
                "module": self.name,
                "used": round(disk.used / (1024**3), 2),
                "total": round(disk.total / (1024**3), 2),
                "percent": disk.percent
            }

        if "battery" in text:

            battery = self.system.battery()

            if battery:

                return {
                    "battery": battery.percent,
                    "charging": battery.power_plugged
                }

            return {
                "battery": "No battery detected"
            }

        return self.system.system()