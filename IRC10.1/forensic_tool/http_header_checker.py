#!/usr/bin/env python3
"""
Herramienta para verificar cabeceras HTTP de una URL.
"""
import argparse
import json
import datetime
import re
from typing import Dict, List, Any
from config import ForensicConstants
from logger import ForensicLogger

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Advertencia: requests no disponible. Verificación de cabeceras HTTP deshabilitada.")

class HttpHeaderChecker:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.constants = ForensicConstants()

    def validate_url(self, url: str) -> bool:
        url_pattern = re.compile(
            r'^https?://'  # protocolo
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # dominio
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'(?::\d+)?'  # puerto opcional
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if not url_pattern.match(url):
            self.logger.log_action("Validación de URL", f"URL inválida: {url}", False)
            return False
        return True

    def check_headers(self, url: str) -> Dict[str, Any]:
        if not REQUESTS_AVAILABLE:
            self.logger.log_action("Verificación de cabeceras", "requests no disponible", False)
            return {"error": "Biblioteca requests no disponible"}
        
        if not self.validate_url(url):
            return {"error": "URL inválida"}
        
        try:
            session = requests.Session()
            retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            response = session.get(url, timeout=30)
            security_headers = {
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'Referrer-Policy': response.headers.get('Referrer-Policy')
            }
            result = {
                "url": url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "security_headers": security_headers,
                "missing_security_headers": [k for k, v in security_headers.items() if v is None]
            }
            self.logger.log_action("Verificación de cabeceras HTTP", f"URL: {url}")
            return result
        except requests.exceptions.RequestException as e:
            self.logger.log_action("Verificación de cabeceras HTTP", f"{url}: {str(e)}", False)
            return {"error": str(e)}

    def generate_report(self, results: Dict[str, Any], output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "http_header_check",
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
    parser = argparse.ArgumentParser(description="Verifica cabeceras HTTP de una URL.")
    parser.add_argument("url", help="URL a analizar")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="http_headers_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    checker = HttpHeaderChecker(logger)
    results = checker.check_headers(args.url)
    report = checker.generate_report(results, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()