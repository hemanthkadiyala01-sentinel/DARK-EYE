import platform
import psutil


class SystemService:

    def cpu(self):
        return psutil.cpu_percent(interval=1)

    def ram(self):
        return psutil.virtual_memory()

    def disk(self):
        return psutil.disk_usage("/")

    def battery(self):
        return psutil.sensors_battery()

    def boot(self):
        return psutil.boot_time()

    def system(self):
        return {
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        }