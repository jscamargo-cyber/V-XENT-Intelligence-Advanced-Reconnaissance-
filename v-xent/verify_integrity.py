import json
import sys
import os

# Add v-xent to path to import utilities
sys.path.append(os.getcwd())

from utils.crypto import IntegrityManager

def verify_latest_report():
    output_dir = "output"
    files = [f for f in os.listdir(output_dir) if f.endswith(".json")]
    if not files:
        print("No se encontraron reportes JSON.")
        return

    latest_file = sorted(files)[-1]
    file_path = os.path.join(output_dir, latest_file)
    
    with open(file_path, "r") as f:
        data = json.load(f)
    
    if IntegrityManager.verify_report(data):
        print(f"[OK] Integridad VERIFICADA para: {latest_file}")
    else:
        print(f"[!] ERROR: La firma de integridad es INVÁLIDA para: {latest_file}")

if __name__ == "__main__":
    verify_latest_report()
