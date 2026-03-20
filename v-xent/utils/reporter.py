import os
import json
from datetime import datetime

class Reporter:
    """
    Generates professional reports in HTML and JSON formats.
    """
    
    def __init__(self, output_dir="output"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_html(self, report_data, target):
        """Generates a professional HTML report."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        risk_level = report_data["summary"]["risk_level"]
        risk_color = "#ff4d4d" if risk_level == "HIGH" else "#ffa64d" if risk_level == "MEDIUM" else "#4dff4d"
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>V-XENT Intelligence Report - {target}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0e0e10; color: #efeff1; margin: 0; padding: 20px; }}
                .container {{ max-width: 1000px; margin: auto; background: #18181b; padding: 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }}
                h1 {{ border-bottom: 2px solid #9147ff; padding-bottom: 10px; color: #9147ff; }}
                .summary {{ display: flex; justify-content: space-between; margin-bottom: 30px; padding: 20px; background: #26262c; border-radius: 5px; }}
                .risk-box {{ text-align: center; padding: 10px 20px; border-radius: 5px; font-weight: bold; background: {risk_color}; color: #000; }}
                .section {{ margin-top: 30px; }}
                .section h2 {{ color: #bf94ff; border-left: 4px solid #bf94ff; padding-left: 10px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #323239; }}
                th {{ background: #26262c; }}
                .tag {{ display: inline-block; background: #9147ff; color: white; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; margin-right: 5px; }}
                footer {{ margin-top: 50px; font-size: 0.8em; text-align: center; color: #71717a; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>V-XENT Intelligence Report</h1>
                <p><strong>Target:</strong> {target} | <strong>Fecha:</strong> {timestamp}</p>
                
                <div class="summary">
                    <div>
                        <p><strong>Riesgo Detectado:</strong></p>
                        <div class="risk-box">{risk_level}</div>
                    </div>
                    <div>
                        <p><strong>Hallazgos Críticos:</strong> {report_data["summary"]["critical_findings"]}</p>
                        <p><strong>Vulnerabilidades:</strong> {report_data["summary"]["total_vulnerabilities"]}</p>
                    </div>
                </div>

                <div class="section">
                    <h2>Análisis de Reputación (VirusTotal)</h2>
                    <table>
                        <tr><th>Métrica</th><th>Valor</th></tr>
                        <tr><td>Puntuación de Reputación</td><td>{report_data["details"]["reputation"].get("reputation_score", "N/A")}</td></tr>
                        <tr><td>Detecciones Maliciosas</td><td>{report_data["details"]["reputation"].get("malicious_count", "N/A")}</td></tr>
                        <tr><td>ASN</td><td>{report_data["details"]["reputation"].get("asn", "N/A")} ({report_data["details"]["reputation"].get("as_owner", "N/A")})</td></tr>
                    </table>
                </div>

                <div class="section">
                    <h2>Exposición de Red (Shodan)</h2>
                    <table>
                        <thead>
                            <tr><th>IP</th><th>Puerto</th><th>Organización</th><th>Transporte</th></tr>
                        </thead>
                        <tbody>
        """
        
        for host in report_data["details"]["network"].get("hosts", []):
            html_content += f"""
                            <tr>
                                <td>{host.get("ip")}</td>
                                <td>{host.get("port")}</td>
                                <td>{host.get("org")}</td>
                                <td>{host.get("transport")}</td>
                            </tr>
            """
            
        html_content += """
                        </tbody>
                    </table>
                </div>

                <footer> Generado por V-XENT Framework - Advanced OSINT Reconnaissance </footer>
            </div>
        </body>
        </html>
        """
        
        file_path = os.path.join(self.output_dir, f"report_{target.replace('.', '_')}.html")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return file_path
