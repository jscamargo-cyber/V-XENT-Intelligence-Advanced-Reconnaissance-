import argparse
import sys
import os
import json
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

from config.config import Config
from utils.logger import setup_logger
from scanners.shodan_scanner import ShodanScanner
from scanners.virustotal_scanner import VirusTotalScanner
from intel_gathering.correlator import ResultsCorrelator
from utils.reporter import Reporter
from utils.validator import InputValidator
from utils.crypto import IntegrityManager

def get_args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="V-XENT - Advanced Reconnaissance OSINT Framework (Secure Ed.)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target options
    parser.add_argument("-t", "--target", help="Único dominio, IP o CIDR")
    parser.add_argument("-f", "--file", help="Archivo con lista de objetivos (uno por línea)")
    
    # Module options
    parser.add_argument("--shodan", action="store_true", help="Módulo Shodan")
    parser.add_argument("--virustotal", action="store_true", help="Módulo VirusTotal")
    
    # Production options
    parser.add_argument("-o", "--output", help="Ruta base de reportes", default="output/report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode Debug")
    parser.add_argument("--json-log", action="store_true", help="Logging estructurado para SIEM")
    parser.add_argument("--safe-mode", action="store_true", help="Hardening extra en reportes")
    
    return parser.parse_args()

def run_scan(target, args, logger):
    """Executes a complete scan for a single target."""
    # 1. Validation
    is_valid, target_type = InputValidator.validate_target(target)
    if not is_valid:
        logger.error(f"Target Omitido: {target} ({target_type})")
        return None

    logger.info(f"Escaneando: {target} [{target_type}]")
    
    shodan_data = None
    vt_data = None

    # 2. Shodan
    if args.shodan:
        scanner = ShodanScanner()
        shodan_data = scanner.get_host_info(target) if target_type == "IP" else scanner.search(target)
        if "error" in shodan_data:
            logger.error(f"Error Shodan ({target}): {shodan_data['error']}")
            shodan_data = None

    # 3. VirusTotal
    if args.virustotal:
        scanner = VirusTotalScanner()
        vt_data = scanner.scan_ip(target) if target_type == "IP" else scanner.scan_domain(target)
        if "error" in vt_data:
            logger.error(f"Error VirusTotal ({target}): {vt_data['error']}")
            vt_data = None

    # 4. Correlation & Reporting
    if shodan_data or vt_data:
        correlator = ResultsCorrelator()
        intel_report = correlator.correlate(shodan_data, vt_data)
        
        # Task 6: Add Integrity Hash (HMAC)
        intel_report = IntegrityManager.sign_report(intel_report)
        intel_report["version"] = Config.VERSION
        
        # Save Outputs
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = InputValidator.sanitize_filename(target)
        
        # JSON Report
        json_path = f"{args.output}_{safe_name}_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(intel_report, f, indent=4)
        logger.info(f"Reporte JSON (firmado) generado: {json_path}")
        
        # HTML Report
        reporter = Reporter()
        html_path = reporter.generate_html(intel_report, target)
        logger.info(f"Reporte HTML (seguro) generado: {html_path}")
        
        return intel_report
    
    return None

def main():
    args = get_args()
    logger = setup_logger(debug=args.verbose)
    
    print(Fore.MAGENTA + Config.BANNER + Style.RESET_ALL)
    logger.info(f"V-XENT v{Config.VERSION} - Secure Intelligence Mode Activated")

    # Config Check
    missing = Config.validate()
    if missing:
        logger.critical(f"CONFIGURACIÓN CRÍTICA FALTANTE: {', '.join(missing)}")
        if args.shodan or args.virustotal:
            sys.exit(1)

    # Gather targets
    targets = []
    if args.target:
        targets.append(args.target)
    if args.file:
        if os.path.exists(args.file):
            with open(args.file, "r") as f:
                targets.extend([line.strip() for line in f if line.strip()])
        else:
            logger.error(f"Archivo de targets no encontrado: {args.file}")

    if not targets:
        logger.error("No se han proporcionado objetivos. Usa -t o -f.")
        sys.exit(1)

    # Process targets
    logger.info(f"Iniciando auditoría para {len(targets)} objetivo(s)...")
    results_summary = []
    for t in targets:
        res = run_scan(t, args, logger)
        if res:
            results_summary.append({
                "target": t,
                "risk": res["summary"]["risk_level"],
                "score": res["summary"]["risk_score"]
            })

    # Final summary for SIEM/CLI
    if args.json_log:
        print(json.dumps(results_summary))
    else:
        print(f"\n{Fore.GREEN}[FIN]{Style.RESET_ALL} Auditoría completada. {len(results_summary)} reportes generados.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        sys.exit(1)
