import os
import json
from datetime import datetime
from pathlib import Path
import bleach
from jinja2 import Environment, FileSystemLoader, select_autoescape
from config.config import Config
from utils.logger import setup_logger

logger = setup_logger("reporter")

class Reporter:
    """
    Security-hardened Reporter for V-XENT.
    Prevents XSS via Bleach/Jinja2 and Path Traversal via Pathlib.
    """
    
    def __init__(self, output_dir="output"):
        # Task 3: Use Pathlib and resolve to prevent Path Traversal
        self.base_dir = Path(__file__).parent.parent.resolve()
        self.output_dir = (self.base_dir / output_dir).resolve()
        
        # Ensure output directory is within the project root
        if not str(self.output_dir).startswith(str(self.base_dir)):
            logger.critical(f"Tentativa de Path Traversal detectada en OUTPUT_DIR: {output_dir}")
            raise ValueError("Directorio de salida inválido")

        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True, exist_ok=True)

        # Task 2: Setup Jinja2 with autoescaping
        template_path = self.base_dir / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(template_path)),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def _sanitize_data(self, data):
        """
        Recursively sanitizes all strings in a dictionary/list using Bleach.
        Task 2: Eliminación total de XSS.
        """
        if isinstance(data, dict):
            return {k: self._sanitize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_data(i) for i in data]
        elif isinstance(data, str):
            # Strip all tags by default for report data
            return bleach.clean(data, tags=[], strip=True)
        return data

    def generate_html(self, report_data, target):
        """
        Generates a secure, professional HTML report using Jinja2 and Bleach.
        """
        logger.info(f"Generando reporte seguro para: {target}")
        
        # Task 2: Sanitize all input data before rendering
        clean_data = self._sanitize_data(report_data)
        clean_target = bleach.clean(target, tags=[], strip=True)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        summary = clean_data.get("summary", {})
        risk_level = summary.get("risk_level", "BAJO")
        
        # Risk levels styling
        risk_config = {
            "BAJO": {"color": "#00ff9d", "bg": "rgba(0, 255, 157, 0.1)"},
            "MEDIO": {"color": "#ffcc00", "bg": "rgba(255, 204, 0, 0.1)"},
            "ALTO": {"color": "#ff3b3b", "bg": "rgba(255, 59, 59, 0.1)"},
            "CRÍTICO": {"color": "#ff00ff", "bg": "rgba(255, 0, 255, 0.1)"}
        }
        cfg = risk_config.get(risk_level, risk_config["BAJO"])

        # Prepare context for Jinja2
        shodan_raw = clean_data.get("raw_data", {}).get("shodan", {})
        shodan_matches = []
        if isinstance(shodan_raw, dict):
            raw_matches = shodan_raw.get("matches", [])
            if not raw_matches and shodan_raw.get("ip"):
                raw_matches = [shodan_raw]
            
            for m in raw_matches:
                shodan_matches.append({
                    "ip": m.get("ip", "N/A"),
                    "ports": m.get("port") or ", ".join(map(str, m.get("ports", []))),
                    "org": m.get("org", "N/A"),
                    "location": m.get("location", {}).get("country_name", "N/A")
                })

        context = {
            "target": clean_target,
            "timestamp": timestamp,
            "risk_level": risk_level,
            "risk_score": summary.get("risk_score", 0),
            "risk_color": cfg["color"],
            "risk_bg": cfg["bg"],
            "total_detections": summary.get("total_detections", 0),
            "critical_findings": summary.get("critical_findings", 0),
            "insights": summary.get("insights", []),
            "vt": clean_data.get("raw_data", {}).get("virustotal", {}),
            "shodan_matches": shodan_matches,
            "version": Config.VERSION
        }

        try:
            template = self.jinja_env.get_template("report.html")
            html_output = template.render(context)
            
            # Task 3: Secure Filename generation
            safe_target = re.sub(r'[^a-zA-Z0-9_\-]', '_', clean_target)
            filename = f"report_{safe_target}_{file_timestamp}.html"
            
            # Using pathlib ensures the file is created in the correct location
            file_path = (self.output_dir / filename).resolve()
            
            # Final check to prevent path traversal on write
            if not str(file_path).startswith(str(self.output_dir)):
                raise ValueError("Path Traversal detectada en generación de nombre de archivo")

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_output)
            
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Error crítico en generación de reporte: {e}")
            raise

import re
