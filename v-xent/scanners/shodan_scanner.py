import shodan
import time
import json
from config.config import Config
from utils.logger import setup_logger

# Initialize logger for this module
logger = setup_logger("shodan_scanner")

class ShodanScanner:
    """
    Shodan Scanner module for V-XENT Framework.
    Provides methods to search for targets and retrieve detailed host information.
    """
    
    def __init__(self):
        """
        Initializes the Shodan API client using the key from Config.
        """
        self.api_key = Config.SHODAN_API_KEY
        if not self.api_key:
            logger.error("Shodan API Key no encontrada. Por favor, configura SHODAN_API_KEY en el archivo .env.")
            self.api = None
        else:
            try:
                self.api = shodan.Shodan(self.api_key)
                logger.info("Módulo ShodanScanner inicializado.")
            except Exception as e:
                logger.error(f"Error al inicializar el cliente de Shodan: {e}")
                self.api = None
        
        # Rate limit settings: 1.1 seconds between requests
        self.last_request_time = 0
        self.rate_limit = 1.1

    def _wait_for_rate_limit(self):
        """
        Ensures a delay of at least 1.1 seconds between API calls.
        """
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            sleep_time = self.rate_limit - elapsed
            logger.debug(f"Rate limiting: esperando {sleep_time:.2f} segundos...")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def search(self, target):
        """
        Search Shodan for a specific target (query, domain, etc.).
        Returns a structured JSON-compatible dictionary.
        """
        if not self.api:
            return {"error": "API de Shodan no configurada"}

        self._wait_for_rate_limit()
        
        try:
            logger.info(f"Ejecutando búsqueda Shodan para: {target}")
            results = self.api.search(target)
            
            # Structure the results for the unified report
            data = {
                "total": results.get("total", 0),
                "matches": []
            }
            
            for match in results.get("matches", []):
                data["matches"].append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "hostnames": match.get("hostnames", []),
                    "org": match.get("org"),
                    "os": match.get("os"),
                    "location": match.get("location", {}),
                    "timestamp": match.get("timestamp"),
                    "isp": match.get("isp"),
                    "asn": match.get("asn"),
                    "transport": match.get("transport")
                })
            
            logger.info(f"Búsqueda completada. {data['total']} resultados encontrados.")
            return data

        except shodan.APIError as e:
            logger.error(f"Error de API de Shodan: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Error inesperado en Shodan search: {e}")
            return {"error": str(e)}

    def get_host_info(self, ip):
        """
        Get detailed information for a specific IP address.
        Returns a structured JSON-compatible dictionary.
        """
        if not self.api:
            return {"error": "API de Shodan no configurada"}

        self._wait_for_rate_limit()

        try:
            logger.info(f"Obteniendo información extendida para la IP: {ip}")
            host = self.api.host(ip)
            
            data = {
                "ip": host.get("ip_str"),
                "org": host.get("org"),
                "os": host.get("os"),
                "ports": host.get("ports", []),
                "last_update": host.get("last_update"),
                "tags": host.get("tags", []),
                "vulns": host.get("vulns", []),
                "services": []
            }
            
            for item in host.get("data", []):
                data["services"].append({
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product"),
                    "version": item.get("version"),
                    "extrainfo": item.get("extrainfo"),
                    "banner": item.get("data", "").strip()[:500] # Limitar banner
                })
            
            logger.info(f"Información de host {ip} recuperada exitosamente.")
            return data

        except shodan.APIError as e:
            logger.error(f"Error de API de Shodan (Host Info): {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Error inesperado en Shodan get_host_info: {e}")
            return {"error": str(e)}
