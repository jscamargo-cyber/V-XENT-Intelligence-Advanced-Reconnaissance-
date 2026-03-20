import argparse
import sys
import os
import json

from config.config import Config
from utils.logger import setup_logger
from scanners.shodan_scanner import ShodanScanner
from scanners.virustotal_scanner import VirusTotalScanner
import re
from intel_gathering.correlator import IntelCorrelator
from utils.reporter import Reporter

def get_args():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="V-XENT - Advanced Reconnaissance OSINT Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Ejemplo: python main.py --target google.com --shodan --virustotal"
    )
    
    # Target options
    parser.add_argument("-t", "--target", help="Dominio, IP o Rango para escaneado", required=True)
    
    # Module options
    parser.add_argument("--shodan", action="store_true", help="Ejecutar escaneo de Shodan")
    parser.add_argument("--virustotal", action="store_true", help="Ejecutar escaneo de VirusTotal")
    
    # Config options
    parser.add_argument("-o", "--output", help="Ruta de salida para el reporte (JSON/HTML)", default="output/report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Habilitar modo debug")
    
    return parser.parse_args()

def main():
    args = get_args()
    
    # Initialize logger
    logger = setup_logger(debug=args.verbose)
    
    # Print Banner
    print(Fore.BLUE + Config.BANNER + Style.RESET_ALL)
    logger.info(f"Iniciando framework V-XENT v{Config.VERSION}")
    logger.info(f"Target: {args.target}")

    # Validate Config
    if not Config.validate():
        logger.warning("Faltan algunas API Keys en el archivo .env. Algunas funcionalidades fallarán.")

    # Module Results Containers
    shodan_results_data = None
    vt_results_data = None

    # Module Execution
    if args.shodan:
        logger.info(f"[*] Iniciando módulo Shodan para: {args.target}")
        shodan_scanner = ShodanScanner()
        
        # Determine if target is IP or query/domain
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        is_ip = re.match(ip_pattern, args.target)
        
        if is_ip:
            shodan_results_data = shodan_scanner.get_host_info(args.target)
        else:
            shodan_results_data = shodan_scanner.search(args.target)
        
        if "error" not in shodan_results_data:
            if is_ip:
                print(f"\n[+] Información de Host Shodan para {args.target}:")
                print(f"    - Org: {shodan_results_data.get('org', 'N/A')}")
                print(f"    - OS: {shodan_results_data.get('os', 'N/A')}")
                print(f"    - Puertos: {', '.join(map(str, shodan_results_data.get('ports', [])))}")
                if shodan_results_data.get('vulns'):
                    print(f"    - Vulnerabilidades: {', '.join(shodan_results_data['vulns'])}")
            else:
                print(f"\n[+] Resultados de Búsqueda Shodan ({shodan_results_data['total']} encontrados):")
                for match in shodan_results_data["matches"][:10]:  # Mostrar solo los 10 primeros por consola
                    print(f"    - IP: {match['ip']} | Puerto: {match['port']} | Org: {match['org']}")
            
            # Guardar resultados
            output_file = f"{args.output}_shodan.json"
            with open(output_file, "w") as f:
                json.dump(shodan_results_data, f, indent=4)
            logger.info(f"Resultados de Shodan guardados en {output_file}")
        else:
            logger.error(f"Error en módulo Shodan: {shodan_results_data['error']}")
    
    if args.virustotal:
        logger.info(f"[*] Iniciando módulo VirusTotal para: {args.target}")
        vt_scanner = VirusTotalScanner()
        
        # Detect if target is IP or Domain
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        if re.match(ip_pattern, args.target):
            vt_results_data = vt_scanner.scan_ip(args.target)
        else:
            vt_results_data = vt_scanner.scan_domain(args.target)
            
        if "error" not in vt_results_data:
            print(f"\n[+] Resultados de VirusTotal para {args.target}:")
            print(f"    - Reputación: {vt_results_data['reputation_score']}")
            print(f"    - Detecciones Maliciosas: {vt_results_data['malicious_count']}")
            print(f"    - ASN: {vt_results_data['asn']} ({vt_results_data['as_owner']})")
            
            # Guardar resultados parciales
            output_file = f"{args.output}_vt.json"
            with open(output_file, "w") as f:
                json.dump(vt_results_data, f, indent=4)
        else:
            logger.error(f"Error en escaneo de VirusTotal: {vt_results_data['error']}")

    # Correlation and Intelligence Gathering
    if shodan_results_data or vt_results_data:
        logger.info("[*] Correlacionando resultados para Inteligencia Unificada...")
        correlator = IntelCorrelator()
        
        intel_report = correlator.correlate(shodan_results_data, vt_results_data)
        print(correlator.get_summary_text(intel_report))
        
        # Save Unified Report (JSON)
        unified_file = f"{args.output}_unified.json"
        with open(unified_file, "w") as f:
            json.dump(intel_report, f, indent=4)
        logger.info(f"Reporte de inteligencia unificado guardado en {unified_file}")

        # Generate HTML Report
        logger.info("[*] Generando reporte HTML profesional...")
        reporter = Reporter()
        html_report_path = reporter.generate_html(intel_report, args.target)
        logger.info(f"[+] Reporte HTML generado con éxito: {html_report_path}")
        print(f"\n[OK] Auditoría completada. Reporte: {html_report_path}")

    if not args.shodan and not args.virustotal:
        logger.warning("No se seleccionó ningún módulo. Usa --shodan o --virustotal.")

if __name__ == "__main__":
    try:
        from colorama import Fore, Style
        main()
    except KeyboardInterrupt:
        print("\n[!] Operación cancelada por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error crítico: {e}")
        sys.exit(1)
