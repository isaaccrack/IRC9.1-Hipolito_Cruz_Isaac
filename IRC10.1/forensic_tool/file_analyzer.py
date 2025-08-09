#!/usr/bin/env python3
"""
Herramienta para analizar archivos (tipo, metadatos, strings, sospechosos).
"""
import argparse
import json
import os
import datetime
import re
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from config import ForensicConstants
from logger import ForensicLogger

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Advertencia: PIL no disponible. Análisis EXIF limitado.")

try:
    from PyPDF2 import PdfReader
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    print("Advertencia: PyPDF2 no disponible. Análisis PDF limitado.")

@dataclass
class FileAnalysis:
    path: str
    size: int
    hashes: Dict[str, str]
    tipo: str
    sospechoso: bool
    metadata: Dict[str, Any]
    strings: List[str]
    created: str
    modified: str
    accessed: str

class FileAnalyzer:
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

    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                hash_objects = {algo: hashlib.new(algo) for algo in self.constants.SUPPORTED_HASH_ALGORITHMS}
                while chunk := f.read(8192):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
                for algo, hash_obj in hash_objects.items():
                    hashes[algo] = hash_obj.hexdigest()
            return hashes
        except Exception as e:
            self.logger.log_action("Cálculo de hash", f"{file_path}: {str(e)}", False)
            return {"error": str(e)}

    def detect_type(self, path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        type_map = {
            '.jpg': 'image/jpeg', '.png': 'image/png', '.pdf': 'application/pdf',
            '.exe': 'application/x-executable', '.dll': 'application/x-msdownload'
        }
        return type_map.get(ext, 'application/octet-stream')

    def is_suspicious(self, path: str, tipo: str) -> bool:
        ext = os.path.splitext(path)[1].lower()
        suspicious_paths = ['/tmp/', 'temp', 'downloads', 'desktop']
        return (ext in self.constants.SUSPICIOUS_EXTENSIONS or 
                'executable' in tipo.lower() or 
                any(path in path.lower() for path in suspicious_paths))

    def extract_strings(self, file_path: str, min_len: int = 4, max_strings: int = 1000) -> List[str]:
        try:
            strings_found = []
            with open(file_path, 'rb') as f:
                content = f.read()
            current_string = ""
            for byte in content:
                if 32 <= byte <= 126:
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_len:
                        strings_found.append(current_string)
                        if len(strings_found) >= max_strings:
                            break
                    current_string = ""
            if current_string and len(current_string) >= min_len:
                strings_found.append(current_string)
            self.logger.log_action("Extracción de strings", f"Archivo: {file_path}, Encontrados: {len(strings_found)}")
            return strings_found
        except Exception as e:
            self.logger.log_action("Extracción de strings", f"{file_path}: {str(e)}", False)
            return []

    def extract_metadata(self, file_path: str, tipo: str) -> Dict[str, Any]:
        info = {
            "file_size": os.path.getsize(file_path),
            "modification_time": datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
            "creation_time": datetime.datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
            "access_time": datetime.datetime.fromtimestamp(os.path.getatime(file_path)).isoformat()
        }
        if 'image' in tipo and PIL_AVAILABLE:
            try:
                with Image.open(file_path) as img:
                    exif_data = img._getexif()
                    if exif_data:
                        info["exif"] = {TAGS.get(tag, tag): str(value) for tag, value in exif_data.items()}
            except Exception as e:
                info["exif_error"] = str(e)
        elif 'pdf' in tipo and PDF_AVAILABLE:
            try:
                with open(file_path, 'rb') as f:
                    reader = PdfReader(f)
                    info["pdf_pages"] = len(reader.pages)
                    if reader.metadata:
                        info["pdf_metadata"] = {k.strip('/'): str(v) for k, v in reader.metadata.items()}
            except Exception as e:
                info["pdf_error"] = str(e)
        self.logger.log_action("Extracción de metadatos", f"Archivo: {file_path}")
        return info

    def analyze_file(self, file_path: str) -> FileAnalysis:
        if not self.validate_file_path(file_path):
            self.logger.log_action("Análisis de archivo", f"Archivo inválido: {file_path}", False)
            return None
        try:
            tipo = self.detect_type(file_path)
            hashes = self.calculate_hashes(file_path)
            if "error" in hashes:
                return None
            sospechoso = self.is_suspicious(file_path, tipo)
            meta = self.extract_metadata(file_path, tipo)
            cadenas = self.extract_strings(file_path) if sospechoso else []
            stat = os.stat(file_path)
            analysis = FileAnalysis(
                path=file_path,
                size=stat.st_size,
                hashes=hashes,
                tipo=tipo,
                sospechoso=sospechoso,
                metadata=meta,
                strings=cadenas,
                created=datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
                modified=datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                accessed=datetime.datetime.fromtimestamp(stat.st_atime).isoformat()
            )
            self.logger.log_action("Análisis de archivo", f"Archivo: {file_path}")
            return analysis
        except Exception as e:
            self.logger.log_action("Análisis de archivo", f"{file_path}: {str(e)}", False)
            return None

    def generate_report(self, analysis: FileAnalysis, output_file: str) -> Dict[str, str]:
        os.makedirs(self.constants.REPORT_DIR, exist_ok=True)
        output_path = os.path.join(self.constants.REPORT_DIR, output_file)
        report_data = {
            "case_id": self.logger.case_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool_version": "3.0",
            "operation": "file_analysis",
            "status": "completed" if analysis else "error",
            "results": asdict(analysis) if analysis else {},
            "errors": ["No se pudo analizar el archivo"] if not analysis else []
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
    parser = argparse.ArgumentParser(description="Analiza un archivo forense.")
    parser.add_argument("file_path", help="Ruta del archivo a analizar")
    parser.add_argument("--output", help="Nombre del archivo de reporte JSON", default="file_analysis_report.json")
    args = parser.parse_args()

    logger = ForensicLogger()
    analyzer = FileAnalyzer(logger)
    analysis = analyzer.analyze_file(args.file_path)
    report = analyzer.generate_report(analysis, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()