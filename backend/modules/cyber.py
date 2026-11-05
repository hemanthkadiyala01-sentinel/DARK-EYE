from backend.modules.base import BaseModule


class CyberModule(BaseModule):

    name = "cyber"

    def execute(self, message):

        return {
            "module": self.name,
            "response": 
            "Cybersecurity analysis activated. "
            "I can analyze threats, malware, phishing, exploits and vulnerabilities."
        }