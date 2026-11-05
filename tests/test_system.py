from backend.modules.system import SystemModule

system = SystemModule()

tests = [
    "cpu",
    "ram",
    "disk",
    "battery",
    "system"
]

for item in tests:
    print("=" * 40)
    print(item)
    print(system.execute(item))