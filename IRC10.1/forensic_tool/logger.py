#!/usr/bin/env python3
"""
Configuración de logging para herramientas forenses.
"""
import logging
import datetime
import os
from config import ForensicConstants

class ForensicLogger:
    def __init__(self, case_id: str = None):
        self.case_id = case_id or f"CASE_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(ForensicConstants.LOG_DIR, exist_ok=True)
        self.log_file = os.path.join(ForensicConstants.LOG_DIR, f"forensic_log_{self.case_id}.log")
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s",
            handlers=[
                logging.FileHandler(self.log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"=== INICIO DE SESIÓN FORENSE - CASO: {self.case_id} ===")

    def log_action(self, action: str, details: str = "", success: bool = True):
        estado = "✔" if success else "❌"
        self.logger.info(f"[{estado}] {action} - {details}")