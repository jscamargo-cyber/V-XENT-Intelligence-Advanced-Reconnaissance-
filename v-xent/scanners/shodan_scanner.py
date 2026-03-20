import shodan
import time
import json
from ratelimit import limits, sleep_and_retry
from config.config import Config
from utils.logger import setup_logger

logger = setup_logger("shodan_scanner")

class ShodanScanner:
    """
    Shodan Scanner for V-XENT Framework.
    Automates host discovery, info retrieval, and exploit search.
    """
    
    def __init__(self):
        """Initialize Shodan API client with rate limiting."""
        self.api_key = Config.SHODAN_API_KEY
        if not self.api_key:
            logger.error("Shodan API Key no encontrada en la configuración.")
            self.api = None
        else:
            self.api = shodan.Shodan(self.api_key)
            logger.info("Shodan Scanner inicializado correctamente.")

    @sleep_and_retry
    @limits(calls=Config.RATE_LIMIT_QUERIES, period=Config.RATE_LIMIT_PERIOD)
    def _rate_limited_call(self, func, *args, **kwargs):
        """Internal helper for rate-limited API calls."""
        return func(*args, **kwargs)

    def search(self, target):
        """
        Search for a target (domain, IP, or query).
        Returns a list of matching hosts.
        """
        if not self.api:
            return {"error": "API no inicializada"}

        try:
            logger.info(f"Buscando target en Shodan: {target}")
            results = self._rate_limited_call(self.api.search, target)
            
            discovery = {
                "total": results.get("total", 0),
                "matches": []
            }
            
            for match in results.get("matches", []):
                discovery["matches"].append({
                    "ip": match.get("ip_str"),
                    "port": match.get("port"),
                    "hostnames": match.get("hostnames", []),
                    "org": match.get("org"),
                    "os": match.get("os"),
                    "transport": match.get("transport")
                })
            
            logger.info(f"Se encontraron {discovery['total']} resultados para {target}")
            return discovery

        except shodan.APIError as e:
            logger.error(f"Error de API en Shodan.search: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Error inesperado en Shodan.search: {e}")
            return {"error": str(e)}

    def get_host_info(self, ip):
        """
        Retrieve detailed information about a specific IP.
        Includes open ports, banners, and vulnerabilities.
        """
        if not self.api:
            return {"error": "API no inicializada"}

        try:
            logger.info(f"Obteniendo información de host: {ip}")
            host = self._rate_limited_call(self.api.host, ip)
            
            host_info = {
                "ip": host.get("ip_str"),
                "org": host.get("org"),
                "os": host.get("os"),
                "ports": host.get("ports", []),
                "last_update": host.get("last_update"),
                "vulns": host.get("vulns", []),
                "services": []
            }
            
            for item in host.get("data", []):
                host_info["services"].append({
                    "port": item.get("port"),
                    "service": item.get("_shodan", {}).get("module"),
                    "banner": item.get("data", "").strip()[:200] + "..." if item.get("data") else None
                })
            
            logger.info(f"Información de host {ip} obtenida con éxito.")
            return host_info

        except shodan.APIError as e:
            logger.error(f"Error de API en Shodan.get_host_info: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Error inesperado en Shodan.get_host_info: {e}")
            return {"error": str(e)}

    def get_exploits(self, cve):
        """
        Search for exploits related to a CVE.
        """
        if not self.api:
            return {"error": "API no inicializada"}

        try:
            logger.info(f"Buscando exploits para: {cve}")
            results = self._rate_limited_call(self.api.exploits.search, cve)
            
            exploits = {
                "total": results.get("total", 0),
                "matches": []
            }
            
            for match in results.get("matches", []):
                exploits["matches"].append({
                    "id": match.get("_id"),
                    "source": match.get("source"),
                    "description": match.get("description"),
                    "platform": match.get("platform")
                })
            
            logger.info(f"Se encontraron {exploits['total']} exploits para {cve}")
            return exploits

        except shodan.APIError as e:
            logger.error(f"Error de API en Shodan.get_exploits: {e}")
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Error inesperado en Shodan.get_exploits: {e}")
            return {"error": str(e)}
