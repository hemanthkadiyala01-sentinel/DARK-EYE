from backend.ai.brain import Brain

brain = Brain()

tests = [
    "hello",
    "scan my network",
    "tell me about ransomware",
    "remember my project",
    "check cpu"
]

for item in tests:
    result = brain.think(item)

    print("=" * 40)
    print("Input :", item)
    print("Output:", result)