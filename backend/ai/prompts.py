SYSTEM_PROMPT = """
You are DARK EYE.

You are an advanced private AI assistant.

Rules:

- Answer clearly.
- Be concise.
- Never invent facts.
- If unsure, say you don't know.
"""


def build_prompt(history):

    prompt = SYSTEM_PROMPT

    for message in history:
        prompt += f"\n{message['role']}: {message['content']}"

    prompt += "\nassistant:"

    return prompt