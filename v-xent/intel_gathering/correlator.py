from utils.logger import setup_logger

logger = setup_logger("correlator")

class IntelCorrelator:
    """
    Correlates intelligence data from multiple sources (Shodan, VirusTotal).
    Generates a unified risk assessment.
    """
    
    def __init__(self):
        self.findings = {}

    def correlate(self, shodan_results=None, vt_results=None):
        """
        Merge results from different scanners into a single intelligence report.
        """
        report = {
            "summary": {
                "risk_level": "LOW",
                "critical_findings": 0,
                "total_vulnerabilities": 0
            },
            "details": {
                "network": {},
                "reputation": {}
            }
        }

        # Process Shodan Data
        if shodan_results and "error" not in shodan_results:
            logger.info("Correlacionando datos de Shodan...")
            report["details"]["network"] = {
                "total_matches": shodan_results.get("total", 0),
                "hosts": shodan_results.get("matches", [])
            }
            # Count vulnerabilities if present in matches
            vulnerabilities = []
            for match in shodan_results.get("matches", []):
                # If we had used get_host_info, we'd have more vulns here
                pass
            report["summary"]["total_vulnerabilities"] = len(vulnerabilities)

        # Process VirusTotal Data
        if vt_results and "error" not in vt_results:
            logger.info("Correlacionando datos de VirusTotal...")
            report["details"]["reputation"] = vt_results
            if vt_results.get("malicious_count", 0) > 0:
                report["summary"]["critical_findings"] += 1
                report["summary"]["risk_level"] = "HIGH"
            elif vt_results.get("suspicious_count", 0) > 0:
                report["summary"]["risk_level"] = "MEDIUM"

        # Logic for combined risk
        if report["summary"]["total_vulnerabilities"] > 5 and report["summary"]["risk_level"] == "MEDIUM":
            report["summary"]["risk_level"] = "HIGH"

        logger.info(f"Correlación completada. Nivel de riesgo detectado: {report['summary']['risk_level']}")
        return report

    def get_summary_text(self, report):
        """Returns a string summary for CLI output."""
        risk = report["summary"]["risk_level"]
        findings = report["summary"]["critical_findings"]
        vulns = report["summary"]["total_vulnerabilities"]
        
        return f"\n--- RESUMEN DE INTELIGENCIA ---\nNivel de Riesgo: {risk}\nHallazgos Críticos: {findings}\nVulnerabilidades Totales: {vulns}\n-------------------------------"
