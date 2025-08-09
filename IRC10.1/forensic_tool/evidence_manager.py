#!/usr/bin/env python3
"""
Herramienta para crear y verificar evidencias forenses.
"""
import argparse
import json
import datetime
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass, asdict, field
from config import ForensicConstants
from logger import ForensicLogger
from hash_calculator import HashCalculator

@dataclass
class ForensicEvidence:
    file_path: str
    original_hash: str
    analysis_start: str
    analysis_end: str = ""
    operations: List[str] = field(default_factory=list)
    final_hash: str = ""
    integrity_verified: bool = False

class EvidenceManager:
    def __init__(self, logger: ForensicLogger):
        self.logger = logger
        self.constants = ForensicConstants()
        self.hash_calculator = HashCalculator(logger)

    def validate_file_path(self, file_path: str) -> bool:
        return self.hash_calculator.validate_file_path(file_path)

    def create_evidence(self, file_path: str) -> Optional[ForensicEvidence]:
        if not self.validate_file_path(file_path):
            self.logger.log_action("Creación de evidencia", f"Archivo inválido: {file_path}", False)
            return None
        
        original_hash = self.hash_calculator.calculate_hashes(file_path, ["sha256"])
        if "error" in original_hash:
            self.logger.log_action("Creación de evidencia", f"Error calculando hash: {file_path} - {original_hash['error']}", False)
            return None
        
        evidence = ForensicEvidence(
            file_path=file_path,
            original_hash=original_hash["sha256"],
            analysis_start=datetime.datetime.now().isoformat()
        )
        self.logger.log_action("Creación de evidencia", f"Archivo: {file_path}, Hash: {original_hash['sha256']}")
        self.logger.log_action("CADENA_CUSTODIA", f"{file_path} - EVIDENCIA_CREADA")
        return evidence

    def verify_integrity(self, evidence: ForensicEvidence) -> bool:
        current_hash = self.hash_calculator.calculate_hashes(evidence.file_path, ["sha256"])
        if "error" in current_hash:
            self.logger.log_action("Verificación de integridad", f"Error calculando hash: {evidence.file_path} - {current_hash['error']}", False)
            return False
        
        evidence.analysis_end = datetime.datetime.now().isoformat()
        evidence.final_hash = current_hash["sha256"]
        integrity_verified = current_hash["sha256"] == evidence.original_hash
        evidence.integrity_verified = integrity_verified
        status = "INTEGRIDAD_VERIFICADA" if integrity_verified else "INTEGRIDAD_COMPROMETIDA"
        self.logger.log_action("Verificación de integridad", f"Archivo: {evidence.file_path}, Estado: {status}")
        self.logger.log_action("CADENA_CUSTODIA", f"{evidence.file_path} - {status}")
        return integrity_verified

    def generate_report(self, evidence: ForensicEvidence, output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "evidence_management",
            "status": "completed" if evidence else "error",
            "results": asdict(evidence) if evidence else {},
            "errors": ["No se pudo crear la evidencia"] if not evidence else []
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
    parser = argparse.ArgumentParser(description="Crea y verifica evidencias forenses.")
    parser.add_argument("file_path", help="Ruta del archivo a gestionar como evidencia")
    parser.add_argument("--verify", action="store_true", help="Verificar integridad de la evidencia")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="evidence_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    manager = EvidenceManager(logger)
    evidence = manager.create_evidence(args.file_path)
    if evidence and args.verify:
        manager.verify_integrity(evidence)
    report = manager.generate_report(evidence, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()