#!/usr/bin/env python3
"""
Herramienta para escanear puertos usando nmap de forma segura.
"""
import argparse
import json
import datetime
import subprocess
import re
import ipaddress
from typing import Dict, List, Any
from dataclasses import dataclass, asdict, field
from config import ForensicConstants
from logger import ForensicLogger

@dataclass
class SecurityScanResult:
    target: str
    scan_type: str
    timestamp: str
    results: Dict[str, Any]
    status: str
    errors: List[str] = field(default_factory=list)

class SecureCommandExecutor:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.constants = ForensicConstants()
        self.command_validators = {'nmap': self._validate_nmap_args}

    def _validate_nmap_args(self, args: List[str]) -> bool:
        dangerous_options = ['-O', '--script', '-sU', '-sS', '-sA', '-sW', '-sM']
        return not any(opt in args for opt in dangerous_options)

    def execute_command(self, command: str, args: List[str], timeout: int = ForensicConstants.DEFAULT_TIMEOUT) -> Dict[str, Any]:
        if command not in self.constants.ALLOWED_COMMANDS:
            self.logger.log_action("Ejecución de comando", f"Comando no permitido: {command}", False)
            return {"error": f"Comando no permitido: {command}"}
        
        if not self.command_validators.get(command, lambda x: True)(args):
            self.logger.log_action("Ejecución de comando", f"Argumentos inválidos para {command}", False)
            return {"error": f"Argumentos inválidos para {command}"}
        
        try:
            self.logger.log_action("Ejecución de comando", f"{command} {' '.join(args)}")
            result = subprocess.run(
                [command] + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return {
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode,
                'command': f"{command} {' '.join(args)}"
            }
        except subprocess.TimeoutExpired:
            self.logger.log_action("Ejecución de comando", f"Timeout ejecutando {command}", False)
            return {"error": "Comando expiró"}
        except FileNotFoundError:
            self.logger.log_action("Ejecución de comando", f"Comando {command} no encontrado", False)
            return {"error": f"Comando {command} no está instalado"}
        except Exception as e:
            self.logger.log_action("Ejecución de comando", f"Error ejecutando {command}: {str(e)}", False)
            return {"error": str(e)}

class PortScanner:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.constants = ForensicConstants()
        self.executor = SecureCommandExecutor(logger)

    def validate_host(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', host):
                return True
            self.logger.log_action("Validación de host", f"Host inválido: {host}", False)
            return False

    def scan_ports(self, host: str, ports: str = "1-1024") -> SecurityScanResult:
        if not self.validate_host(host):
            return SecurityScanResult(
                target=host,
                scan_type="port_scan",
                timestamp=datetime.datetime.now().isoformat(),
                results={},
                status="error",
                errors=["Host inválido"]
            )
        
        args = ["-p", ports, "-T4", "--open", host]
        result = self.executor.execute_command("nmap", args)
        scan_result = SecurityScanResult(
            target=host,
            scan_type="port_scan",
            timestamp=datetime.datetime.now().isoformat(),
            results=result,
            status="completed" if "error" not in result else "error",
            errors=[result.get("error", "")] if "error" in result else []
        )
        self.logger.log_action("Escaneo de puertos", f"Host: {host}, Puertos: {ports}")
        return scan_result

    def generate_report(self, scan_result: SecurityScanResult, output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "port_scan",
            "status": scan_result.status,
            "results": asdict(scan_result),
            "errors": scan_result.errors
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
    parser = argparse.ArgumentParser(description="Escanea puertos de un host usando nmap.")
    parser.add_argument("host", help="IP o dominio objetivo")
    parser.add_argument("--ports", help="Puertos a escanear (e.g., 1-1024)", default="1-1024")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="port_scan_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    scanner = PortScanner(logger)
    scan_result = scanner.scan_ports(args.host, args.ports)
    report = scanner.generate_report(scan_result, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()