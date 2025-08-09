#!/usr/bin/env python3
"""
Herramienta para escanear directorios en busca de archivos sospechosos.
"""
import argparse
import json
import os
import datetime
from pathlib import Path
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import ForensicConstants
from logger import ForensicLogger
from file_analyzer import FileAnalyzer, FileAnalysis

class DirectoryScanner:
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

    def scan_directory(self, dir_path: str, deep_scan: bool = False) -> Dict[str, Any]:
        if not self.validate_directory_path(dir_path):
            return {"error": "Directorio inválido"}
        
        results = {"summary": {}, "suspicious_files": [], "file_analysis": [], "statistics": {}}
        all_files = []
        suspicious_files = []
        
        try:
            for root, _, files in os.walk(dir_path):
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    all_files.append(full_path)
                    if self.analyzer.is_suspicious(full_path, self.analyzer.detect_type(full_path)):
                        suspicious_files.append(full_path)
            
            results["suspicious_files"] = suspicious_files
            if deep_scan:
                with ThreadPoolExecutor(max_workers=4) as executor:
                    future_to_file = {executor.submit(self.analyzer.analyze_file, f): f for f in all_files[:100]}
                    for future in as_completed(future_to_file):
                        try:
                            analysis = future.result()
                            if analysis:
                                results["file_analysis"].append(asdict(analysis))
                        except Exception as e:
                            self.logger.log_action("Análisis profundo", f"{future_to_file[future]}: {str(e)}", False)
            
            results["statistics"] = {
                "total_files": len(all_files),
                "suspicious_files": len(suspicious_files),
                "analyzed_files": len(results["file_analysis"])
            }
            self.logger.log_action("Escaneo de directorio", f"Ruta: {dir_path}, Archivos: {len(all_files)}")
            return results
        except Exception as e:
            self.logger.log_action("Escaneo de directorio", f"{dir_path}: {str(e)}", False)
            return {"error": str(e)}

    def generate_report(self, results: Dict[str, Any], output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "directory_scan",
            "status": "completed" if "error" not in results else "error",
            "results": results,
            "errors": [results.get("error", "")] if "error" in results else []
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
    parser = argparse.ArgumentParser(description="Escanea un directorio en busca de archivos sospechosos.")
    parser.add_argument("dir_path", help="Ruta del directorio a escanear")
    parser.add_argument("--deep", action="store_true", help="Realizar análisis profundo de archivos")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="directory_scan_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    scanner = DirectoryScanner(logger)
    results = scanner.scan_directory(args.dir_path, args.deep)
    report = scanner.generate_report(results, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()