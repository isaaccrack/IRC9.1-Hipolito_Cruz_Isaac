#!/usr/bin/env python3
"""
Configuración compartida para herramientas forenses.
"""

class ForensicConstants:
    SUPPORTED_HASH_ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
    SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".msi", ".jar"}
    ALLOWED_COMMANDS = ["nmap"]
    MAX_FILE_SIZE = 1024 * 1024 * 1024  # 1GB
    DEFAULT_TIMEOUT = 300  # 5 minutos
    LOG_DIR = "logs"
    REPORT_DIR = "reports"