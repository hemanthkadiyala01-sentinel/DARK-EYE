import platform
import psutil


def cpu_usage():
    return {
        "cpu_percent": psutil.cpu_percent(interval=1)
    }


def ram_usage():
    memory = psutil.virtual_memory()

    return {
        "total_gb": round(memory.total / (1024**3), 2),
        "used_gb": round(memory.used / (1024**3), 2),
        "percent": memory.percent,
    }


def disk_usage():
    disk = psutil.disk_usage("/")

    return {
        "total_gb": round(disk.total / (1024**3), 2),
        "used_gb": round(disk.used / (1024**3), 2),
        "percent": disk.percent,
    }


def system_info():
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
    }