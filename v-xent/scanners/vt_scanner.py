import requests
import json
import time
from ratelimit import limits, sleep_and_retry
from config.config import Config
from utils.logger import setup_logger

logger = setup_logger("vt_scanner")

class VirusTotalScanner:
    """
    VirusTotal Scanner for V-XENT Framework.
    Utilizes VT API v3 for domain, IP, and URL reputation analysis.
    """
    
    def __init__(self):
        """Initialize VirusTotal API scanner with headers."""
        self.api_key = Config.VT_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        if not self.api_key:
            logger.error("VirusTotal API Key no encontrada en la configuración.")
        else:
            logger.info("VirusTotal Scanner inicializado correctamente.")

    @sleep_and_retry
    @limits(calls=4, period=60)  # Límite estándar de VT Free: 4 req/min
    def _make_request(self, endpoint):
        """Internal helper for rate-limited requests to VT v3."""
        url = f"{self.base_url}/{endpoint}"
        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                logger.warning("Rate limit de VirusTotal alcanzado. Esperando...")
            logger.error(f"Error HTTP en VirusTotal ({response.status_code}): {e}")
            return {"error": f"HTTP {response.status_code}", "details": str(e)}
        except Exception as e:
            logger.error(f"Error inesperado en comunicación con VirusTotal: {e}")
            return {"error": "Unexpected Error", "details": str(e)}

    def scan_ip(self, ip):
        """Retrieve reputation and info for an IP address."""
        logger.info(f"Analizando IP en VirusTotal: {ip}")
        result = self._make_request(f"ip_addresses/{ip}")
        return self._process_reputation(result, "IP", ip)

    def scan_domain(self, domain):
        """Retrieve reputation and info for a domain."""
        logger.info(f"Analizando dominio en VirusTotal: {domain}")
        result = self._make_request(f"domains/{domain}")
        return self._process_reputation(result, "Dominio", domain)

    def _process_reputation(self, result, target_type, target_value):
        """Process the raw JSON response from VT into a structured format."""
        if "error" in result:
            return result

        try:
            data = result.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            reputation = {
                "target": target_value,
                "type": target_type,
                "reputation_score": attributes.get("reputation", 0),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "undetected_count": stats.get("undetected", 0),
                "harmless_count": stats.get("harmless", 0),
                "asn": attributes.get("asn", "N/A"),
                "as_owner": attributes.get("as_owner", "N/A"),
                "tags": attributes.get("tags", []),
                "categories": attributes.get("categories", {})
            }
            
            summary = f"{target_type} {target_value}: {reputation['malicious_count']} motores detectaron actividad maliciosa."
            if reputation['malicious_count'] > 0:
                logger.warning(summary)
            else:
                logger.info(summary)
                
            return reputation

        except Exception as e:
            logger.error(f"Error al procesar respuesta de VirusTotal: {e}")
            return {"error": "Processing Error", "details": str(e)}
