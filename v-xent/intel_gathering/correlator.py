from utils.logger import setup_logger

# Initialize logger for this module
logger = setup_logger("correlator")

class ResultsCorrelator:
    """
    Correlates intelligence data from Shodan and VirusTotal.
    Analyzes overlaps, open ports, and threat detections to provide a unified risk assessment.
    """
    
    def __init__(self):
        self.risk_levels = {
            "BAJO": "LOW",
            "MEDIO": "MEDIUM",
            "ALTO": "HIGH",
            "CRÍTICO": "CRITICAL"
        }

    def correlate(self, shodan_results=None, vt_results=None):
        """
        Consolidates results from different sources into a single intelligence report.
        """
        report = {
            "summary": {
                "risk_level": "BAJO",
                "risk_score": 0,  # 0-100 scale
                "critical_findings": 0,
                "total_detections": 0,
                "insights": []
            },
            "correlations": {
                "overlapping_ips": [],
                "suspicious_ports": [],
                "threat_matches": []
            },
            "raw_data": {
                "shodan": shodan_results,
                "virustotal": vt_results
            }
        }

        # Analyze VirusTotal Results
        if vt_results and "error" not in vt_results:
            malicious = vt_results.get("malicious_count", 0)
            suspicious = vt_results.get("suspicious_count", 0)
            
            report["summary"]["total_detections"] += malicious
            if malicious > 0:
                report["summary"]["risk_score"] += (malicious * 20)
                report["summary"]["critical_findings"] += 1
                report["summary"]["insights"].append(f"VirusTotal detectó {malicious} motores marcando el objetivo como malicioso.")
            elif suspicious > 0:
                report["summary"]["risk_score"] += 15
                report["summary"]["insights"].append("VirusTotal detectó actividad sospechosa.")

        # Analyze Shodan Results
        if shodan_results and "error" not in shodan_results:
            # If search results (list of matches)
            matches = shodan_results.get("matches", [])
            # If single host info
            if not matches and shodan_results.get("ip"):
                matches = [shodan_results]
            
            ports_found = set()
            for match in matches:
                ip = match.get("ip")
                ports = match.get("ports", [])
                if not ports and match.get("port"):
                    ports = [match.get("port")]
                
                for p in ports:
                    ports_found.add(p)
                    # Detect suspicious/sensitive ports
                    if p in [21, 22, 23, 445, 3389, 5900]:
                        report["correlations"]["suspicious_ports"].append({"ip": ip, "port": p})
                        report["summary"]["risk_score"] += 10
            
            if report["correlations"]["suspicious_ports"]:
                report["summary"]["insights"].append(f"Se detectaron {len(report['correlations']['suspicious_ports'])} puertos sensibles abiertos (ej. SSH, RDP, SMB).")

            # Look for overlaps if Target in VT matches IPs in Shodan
            if vt_results and vt_results.get("target"):
                target_ip = vt_results.get("target")
                for match in matches:
                    if match.get("ip") == target_ip:
                        report["correlations"]["overlapping_ips"].append(target_ip)
                        if vt_results.get("malicious_count", 0) > 0:
                            report["summary"]["risk_score"] += 30
                            report["summary"]["insights"].append(f"¡ALERTA!: La IP {target_ip} identificada por Shodan está marcada como MALICIOSA en VirusTotal.")

        # Normalize Risk Level
        score = report["summary"]["risk_score"]
        if score >= 80:
            report["summary"]["risk_level"] = "ALTO"
        elif score >= 40:
            report["summary"]["risk_level"] = "MEDIO"
        else:
            report["summary"]["risk_level"] = "BAJO"

        logger.info(f"Correlación finalizada. Riesgo: {report['summary']['risk_level']} (Score: {score})")
        return report

    def get_summary_text(self, report):
        """
        Returns a human-readable summary for console display.
        """
        summary = report["summary"]
        text = f"\n{'='*40}\n"
        text += f" RESUMEN DE INTELIGENCIA CORRELACIONADA\n"
        text += f"{'='*40}\n"
        text += f" Nivel de Riesgo: {summary['risk_level']}\n"
        text += f" Detecciones Totales: {summary['total_detections']}\n"
        text += f" Hallazgos Críticos: {summary['critical_findings']}\n"
        text += f"{'-'*40}\n"
        text += " INSIGHTS:\n"
        for insight in summary["insights"]:
            text += f" [!] {insight}\n"
        text += f"{'='*40}\n"
        return text
