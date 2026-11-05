from backend.core.file_manager import FileManager
from backend.core.logger import get_logger
from backend.modules.file_intelligence import FileIntelligence


class DarkEyeCore:

    def __init__(self):

        self.logger = get_logger()

        self.file_manager = FileManager()

        self.file_intelligence = FileIntelligence()

        self.logger.info(
            "DARK-EYE Core initialized"
        )


    def scan_system(self, path):

        self.logger.info(
            f"Scanning directory: {path}"
        )

        files = self.file_manager.scan_directory(path)

        self.logger.info(
            f"Found {len(files)} files"
        )

        return files



    def analyze_file(self, path):

        self.logger.info(
            f"Analyzing file: {path}"
        )

        return self.file_intelligence.analyze(path)



    def analyze_folder(self, path):

        self.logger.info(
            f"Starting folder intelligence scan: {path}"
        )


        files = self.file_manager.scan_directory(path)


        report = {

            "total_files": 0,

            "categories": {},

            "risk_levels": {},

            "high_risk_files": []

        }


        for file in files:

            if not file.is_file():
                continue


            try:

                analysis = self.file_intelligence.analyze(file)


                report["total_files"] += 1


                file_type = analysis["type"]

                risk = analysis["risk"]


                report["categories"][file_type] = (
                    report["categories"].get(file_type, 0) + 1
                )


                report["risk_levels"][risk] = (
                    report["risk_levels"].get(risk, 0) + 1
                )


                if risk == "HIGH":

                    report["high_risk_files"].append(
                        file.name
                    )


            except Exception as error:

                self.logger.error(
                    f"Failed analyzing {file}: {error}"
                )


        self.logger.info(
            "Folder intelligence scan completed"
        )


        return report