#!/usr/bin/env python3
"""
Herramienta para extraer Indicadores de Compromiso (IoCs) de texto.
"""
import argparse
import json
import datetime
import re
from typing import List
from dataclasses import dataclass, asdict
from config import ForensicConstants
from logger import ForensicLogger

@dataclass
class IoC:
    ips: List[str]
    ipv6: List[str]
    domains: List[str]
    urls: List[str]
    emails: List[str]
    hashes: List[str]
    file_paths: List[str]
    registry_keys: List[str]

class IoCExtractor:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.constants = ForensicConstants()

    def extract_iocs(self, text: str) -> IoC:
        try:
            iocs = IoC(
                ips=list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))),
                ipv6=list(set(re.findall(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b', text))),
                domains=list(set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b', text))),
                urls=list(set(re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', text))),
                emails=list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text))),
                hashes=list(set(re.findall(r'\b[a-fA-F0-9]{32,64}\b', text))),
                file_paths=list(set(re.findall(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*', text))),
                registry_keys=list(set(re.findall(r'HKEY_[A-Z_]+\\[^\\/:*?"<>|\r\n]+', text)))
            )
            total_iocs = sum(len(getattr(iocs, field)) for field in iocs.__dataclass_fields__)
            self.logger.log_action("Extracción de IoCs", f"Encontrados: {total_iocs}")
            return iocs
        except Exception as e:
            self.logger.log_action("Extracción de IoCs", str(e), False)
            return IoC([], [], [], [], [], [], [], [])

    def generate_report(self, iocs: IoC, output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "ioc_extraction",
            "status": "completed",
            "results": asdict(iocs),
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
    parser = argparse.ArgumentParser(description="Extrae IoCs de un texto.")
    parser.add_argument("text_file", help="Ruta del archivo de texto a analizar")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="ioc_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    extractor = IoCExtractor(logger)
    try:
        with open(args.text_file, 'r', encoding='utf-8') as f:
            text = f.read()
        iocs = extractor.extract_iocs(text)
        report = extractor.generate_report(iocs, args.output)
        print(json.dumps(report, indent=2, ensure_ascii=False))
    except Exception as e:
        logger.log_action("Lectura de archivo", f"{args.text_file}: {str(e)}", False)
        print(json.dumps({"error": str(e)}, indent=2))

if __name__ == "__main__":
    main()