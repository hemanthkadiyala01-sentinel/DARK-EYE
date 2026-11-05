class Dispatcher:

    def route(self, message: str):

        text = message.lower()

        if any(word in text for word in [
            "hack",
            "malware",
            "virus",
            "phishing",
            "threat",
            "exploit",
            "ransomware"
        ]):
            return "cyber"

        elif any(word in text for word in [
            "research",
            "paper",
            "article",
            "summarize"
        ]):
            return "research"

        elif any(word in text for word in [
            "cpu",
            "ram",
            "battery",
            "disk",
            "system"
        ]):
            return "system"

        elif any(word in text for word in [
            "scan",
            "network",
            "ip",
            "port"
        ]):
            return "network"

        elif any(word in text for word in [
            "remember",
            "memory",
            "note"
        ]):
            return "memory"

        return "chat"