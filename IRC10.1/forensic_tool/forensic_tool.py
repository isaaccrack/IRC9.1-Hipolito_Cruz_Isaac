# forensic_tool.py
from evidence_manager import EvidenceManager
from file_analyzer import FileAnalyzer
# ... importar otros módulos ...
from logger import ForensicLogger

def main():
    logger = ForensicLogger()
    print("=== HERRAMIENTA FORENSE UNIFICADA ===")
    print("1. Gestionar evidencia")
    print("2. Analizar archivo")
    # ... otras opciones ...
    choice = input("Selecciona una opción: ")
    if choice == "1":
        file_path = input("Ruta del archivo: ")
        manager = EvidenceManager(logger)
        evidence = manager.create_evidence(file_path)
        # ... manejar otras opciones ...
    # ... continuar con otras funcionalidades ...

if __name__ == "__main__":
    main()