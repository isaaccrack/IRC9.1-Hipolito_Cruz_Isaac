#!/usr/bin/env python3
"""
Herramienta para consolidar y generar reportes JSON de análisis forense.
"""
import argparse
import json
import os
import datetime
from typing import Dict, Any
from config import ForensicConstants
from logger import ForensicLogger

class ReportGenerator:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.constants = ForensicConstants()

    def generate_report(self, data: Dict[str, Any], output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "consolidated_report",
            "status": "completed",
            "results": data,
            "errors": []
        }
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            self.logger.log_action("Reporte JSON generado", f"Archivo: {output_path}")
            return {"report_file": output_path, "format": "json"}
        except Exception as e:
            self.logger.log_action("Generación de reporte", f"{output_path}: {str(e)}", False)
            return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="Consolida reportes forenses en un archivo JSON.")
    parser.add_argument("input_files", help="Archivos JSON de entrada separados por coma")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="consolidated_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    generator = ReportGenerator(logger)
    consolidated_data = {}
    input_files = args.input_files.split(',')
    
    for input_file in input_files:
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                operation = data.get("operation", os.path.basename(input_file))
                consolidated_data[operation] = data
        except Exception as e:
            logger.log_action("Lectura de archivo", f"{input_file}: {str(e)}", False)
            consolidated_data[os.path.basename(input_file)] = {"error": str(e)}
    
    report = generator.generate_report(consolidated_data, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()