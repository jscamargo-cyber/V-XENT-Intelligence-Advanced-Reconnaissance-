import requests
import json
import time
from config.config import Config
from utils.logger import setup_logger

# Initialize logger for this module
logger = setup_logger("virustotal_scanner")

class VirusTotalScanner:
    """
    VirusTotal Scanner module for V-XENT Framework.
    Utilizes VirusTotal API v3 for domain and IP reputation analysis.
    """
    
    def __init__(self):
        """
        Initializes the VirusTotal API client with key from Config.
        """
        self.api_key = Config.VT_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
        if not self.api_key:
            logger.error("VirusTotal API Key no encontrada. Por favor, configura VT_API_KEY en el archivo .env.")
        else:
            logger.info("Módulo VirusTotalScanner inicializado.")
        
        # Rate limit settings: 4 requests per minute (15 seconds between requests)
        self.last_request_time = 0
        self.rate_limit = 15.1 

    def _wait_for_rate_limit(self):
        """
        Ensures a delay of at least 15 seconds between API calls to respect VT Free plan limits.
        """
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            sleep_time = self.rate_limit - elapsed
            logger.debug(f"Rate limiting VT: esperando {sleep_time:.2f} segundos...")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _make_request(self, endpoint):
        """
        Internal helper to make GET requests to VT API.
        """
        if not self.api_key:
            return {"error": "API key de VirusTotal no configurada"}

        self._wait_for_rate_limit()
        url = f"{self.base_url}/{endpoint}"
        
        try:
            response = requests.get(url, headers=self.headers)
            if response.status_code == 401:
                return {"error": "API key inválida o no autorizada"}
            if response.status_code == 429:
                return {"error": "Cuota de API de VirusTotal excedida"}
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Error HTTP en VirusTotal: {e}")
            return {"error": f"Error HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Error inesperado en VirusTotal request: {e}")
            return {"error": str(e)}

    def scan_ip(self, ip):
        """
        Retrieves reputation information for an IP address.
        """
        logger.info(f"Analizando IP en VirusTotal: {ip}")
        result = self._make_request(f"ip_addresses/{ip}")
        return self._process_results(result, "IP", ip)

    def scan_domain(self, domain):
        """
        Retrieves reputation information for a domain.
        """
        logger.info(f"Analizando dominio en VirusTotal: {domain}")
        result = self._make_request(f"domains/{domain}")
        return self._process_results(result, "Domain", domain)

    def get_report(self, resource_type, resource_id):
        """
        Generic method to get a report for a specific resource.
        """
        endpoint = f"{resource_type}/{resource_id}"
        return self._make_request(endpoint)

    def _process_results(self, result, target_type, target_value):
        """
        Processes raw VT v3 response into a structured format.
        """
        if "error" in result:
            return result

        try:
            data = result.get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            processed = {
                "target": target_value,
                "type": target_type,
                "reputation_score": attributes.get("reputation", 0),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "undetected_count": stats.get("undetected", 0),
                "harmless_count": stats.get("harmless", 0),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "tags": attributes.get("tags", []),
                "categories": attributes.get("categories", {})
            }
            
            # Log specific findings
            if processed["malicious_count"] > 0:
                logger.warning(f"Detecciones maliciosas encontradas para {target_value}: {processed['malicious_count']}")
            else:
                logger.info(f"No se encontraron detecciones maliciosas para {target_value}.")
                
            return processed

        except Exception as e:
            logger.error(f"Error al procesar resultados de VirusTotal: {e}")
            return {"error": "Error de procesamiento de datos"}
