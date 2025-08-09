#!/usr/bin/env python3
"""
Herramienta para calcular hashes de archivos.
"""
import argparse
import hashlib
import json
import os
import datetime
from pathlib import Path
from typing import Dict, List
from config import ForensicConstants
from logger import ForensicLogger

class HashCalculator:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.constants = ForensicConstants()

    def validate_file_path(self, file_path: str) -> bool:
        try:
            path = Path(file_path).resolve()
            if not path.exists():
                self.logger.log_action("Validación de archivo", f"Archivo no existe: {file_path}", False)
                return False
            if not path.is_file():
                self.logger.log_action("Validación de archivo", f"No es un archivo: {file_path}", False)
                return False
            if path.stat().st_size > self.constants.MAX_FILE_SIZE:
                self.logger.log_action("Validación de archivo", f"Archivo excede tamaño máximo: {file_path}", False)
                return False
            return True
        except (OSError, ValueError) as e:
            self.logger.log_action("Validación de archivo", f"Error: {file_path} - {str(e)}", False)
            return False

    def calculate_hashes(self, file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
        algorithms = [algo.lower() for algo in (algorithms or self.constants.SUPPORTED_HASH_ALGORITHMS)]
        invalid_algorithms = [algo for algo in algorithms if algo not in self.constants.SUPPORTED_HASH_ALGORITHMS]
        if invalid_algorithms:
            self.logger.log_action("Cálculo de hash", f"Algoritmos no soportados: {', '.join(invalid_algorithms)}", False)
            return {"error": f"Algoritmos no soportados: {', '.join(invalid_algorithms)}"}
        
        if not self.validate_file_path(file_path):
            return {"error": "Archivo inválido"}
        
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                hash_objects = {algo: hashlib.new(algo) for algo in algorithms}
                while chunk := f.read(8192):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
                for algo, hash_obj in hash_objects.items():
                    hashes[algo] = hash_obj.hexdigest()
            self.logger.log_action("Cálculo de hash", f"Archivo: {file_path}, Algoritmos: {', '.join(algorithms)}")
            return hashes
        except Exception as e:
            self.logger.log_action("Cálculo de hash", f"{file_path}: {str(e)}", False)
            return {"error": str(e)}

    def generate_report(self, results: Dict[str, str], output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "hash_calculation",
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
    parser = argparse.ArgumentParser(description="Calcula hashes de un archivo.")
    parser.add_argument("file_path", help="Ruta del archivo a analizar")
    parser.add_argument("--algorithms", help="Algoritmos de hash separados por coma (md5,sha1,sha256,sha512)", default="md5,sha256")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="hash_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    calculator = HashCalculator(logger)
    algorithms = args.algorithms.split(',')
    results = calculator.calculate_hashes(args.file_path, algorithms)
    report = calculator.generate_report(results, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()