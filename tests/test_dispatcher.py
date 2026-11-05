import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

sys.path.append(
    str(PROJECT_ROOT)
)


from backend.ai.dispatcher import Dispatcher


dispatcher = Dispatcher()


messages = [
    "tell me about ransomware",
    "check my cpu usage",
    "scan my network",
    "remember my project name",
    "hello"
]


for message in messages:
    module = dispatcher.route(message)

    print(
        f"{message} ---> {module}"
    )