#!/usr/bin/env python3
"""
Herramienta para generar líneas de tiempo forenses basadas en timestamps de archivos.
"""
import argparse
import json
import os
import datetime
from pathlib import Path
from typing import Dict, List, Any
from config import ForensicConstants
from logger import ForensicLogger
from file_analyzer import FileAnalyzer

class TimelineGenerator:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.constants = ForensicConstants()
        self.analyzer = FileAnalyzer(logger)

    def validate_directory_path(self, dir_path: str) -> bool:
        try:
            path = Path(dir_path).resolve()
            if not path.exists():
                self.logger.log_action("Validación de directorio", f"Directorio no existe: {dir_path}", False)
                return False
            if not path.is_dir():
                self.logger.log_action("Validación de directorio", f"No es un directorio: {dir_path}", False)
                return False
            return True
        except (OSError, ValueError) as e:
            self.logger.log_action("Validación de directorio", f"Error: {dir_path} - {str(e)}", False)
            return False

    def generate_timeline(self, dir_path: str) -> List[Dict[str, Any]]:
        if not self.validate_directory_path(dir_path):
            self.logger.log_action("Generación de línea de tiempo", f"Directorio inválido: {dir_path}", False)
            return [{"error": "Directorio inválido"}]
        
        timeline = []
        try:
            for root, _, files in os.walk(dir_path):
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    try:
                        stat = os.stat(full_path)
                        timeline.append({
                            "file": full_path,
                            "size": stat.st_size,
                            "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "accessed": datetime.datetime.fromtimestamp(stat.st_atime).isoformat(),
                            "type": self.analyzer.detect_type(full_path)
                        })
                    except (OSError, PermissionError):
                        self.logger.log_action("Procesamiento de archivo", f"Error: {full_path}", False)
                        continue
            timeline.sort(key=lambda x: x["modified"])
            self.logger.log_action("Generación de línea de tiempo", f"Ruta: {dir_path}, Entradas: {len(timeline)}")
            return timeline
        except Exception as e:
            self.logger.log_action("Generación de línea de tiempo", f"{dir_path}: {str(e)}", False)
            return [{"error": str(e)}]

    def generate_report(self, timeline: List[Dict[str, Any]], output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "timeline_generation",
            "status": "completed" if timeline and "error" not in timeline[0] else "error",
            "results": timeline,
            "errors": [timeline[0]["error"]] if timeline and "error" in timeline[0] else []
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
    parser = argparse.ArgumentParser(description="Genera una línea de tiempo forense de un directorio.")
    parser.add_argument("dir_path", help="Ruta del directorio a analizar")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="timeline_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    generator = TimelineGenerator(logger)
    timeline = generator.generate_timeline(args.dir_path)
    report = generator.generate_report(timeline, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()