# V-XENT: Intelligence Advanced Reconnaissance Framework [SECURE ED.] 🛡️
> **Motor Avanzado de Inteligencia y Reconocimiento OSINT**
> *Desarrollado por jscamargo-cyber*

![Version](https://img.shields.io/badge/version-1.1.0--secure-purple.svg?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)

**V-XENT** es un motor de reconocimiento OSINT de nivel profesional, diseñado para equipos de Red Team e investigadores de seguridad. Esta edición segura ha sido endurecida (hardened) para su uso en entornos corporativos y auditorías de clientes, garantizando la integridad de los datos y la seguridad del operador.

---

## 🚀 Características Clave

*   **Inteligencia Multi-Fuente**: Descubrimiento automatizado de infraestructura vía Shodan y análisis de reputación mediante VirusTotal API v3.
*   **Motor de Correlación Avanzado**: Cruce inteligente de datos para identificar activos de alto riesgo y amenazas críticas.
*   **Reportes de Nivel Profesional**: Generación de reportes HTML seguros (Jinja2 + Bleach) y salidas JSON con **firmas de integridad HMAC-SHA256**.
*   **Validación Estricta de Entradas**: Protección contra ataques de inyección mediante sanitización profunda de objetivos (IP, Dominios, CIDR).
*   **Stack Docker Empresarial**: Construcción multi-etapa, usuarios no-root y sistema de archivos de solo lectura para máxima seguridad.
*   **Escaneo por Lotes**: Soporte para procesar múltiples objetivos desde archivos de texto.

---

## ⚠️ SEGURIDAD Y BUENAS PRÁCTICAS

**Este framework sigue una filosofía de "Seguridad por Diseño". Para mantener la máxima protección:**

1.  **Gestión de APIs**: 
    - **NUNCA** subas tu archivo `.env` al repositorio. Está ignorado por defecto en `.gitignore`.
    - En producción, usa **Variables de Entorno** o **Docker Secrets**.
2.  **Integridad de Reportes**: 
    - Cada reporte JSON incluye un `integrity_hash`. Puedes verificarlo usando la utilidad `IntegrityManager.verify_report()` para asegurar que los datos no han sido alterados.
3.  **Despliegue Seguro**: 
    - Se recomienda ejecutar V-XENT dentro de su **Contenedor Docker Hardened**.

---

## 📦 Guía de Instalación Paso a Paso

Elige el método que prefieras para correr el proyecto de forma rápida y sencilla.

### Opción A: Despliegue con Docker (Recomendado ⭐)
Ideal para entornos aislados y seguros. No requiere instalar dependencias en tu sistema.

1.  **Clonar el repositorio:**
    ```bash
    git clone https://github.com/jscamargo-cyber/V-XENT-Intelligence-Advanced-Reconnaissance-.git
    cd V-XENT-Intelligence-Advanced-Reconnaissance-
    ```
2.  **Configurar credenciales:**
    Copia el archivo de ejemplo y añade tus API Keys de Shodan y VirusTotal:
    ```bash
    cp config/.env.example .env
    # Edita el archivo .env con tus llaves
    ```
3.  **Construir y ejecutar:**
    ```bash
    docker compose build
    docker compose run v-xent --target google.com --shodan --virustotal
    ```

---

### Opción B: Instalación Local (Git Clone)
Ideal para desarrollo o si prefieres correrlo directamente sobre Python.

1.  **Clonar el repositorio:**
    ```bash
    git clone https://github.com/jscamargo-cyber/V-XENT-Intelligence-Advanced-Reconnaissance-.git
    cd V-XENT-Intelligence-Advanced-Reconnaissance-
    ```
2.  **Instalar dependencias del sistema:**
    (En Linux/Debian): `sudo apt install libpangocairo-1.0-0 libharfbuzz-dev`
3.  **Crear entorno virtual e instalar librerías:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
4.  **Configurar credenciales:**
    ```bash
    cp config/.env.example .env
    # Edita el archivo .env con tus llaves
    ```
5.  **Ejecutar el framework:**
    ```bash
    python3 main.py --target 8.8.8.8 --shodan --virustotal
    ```

---

## 🖥️ Ejemplos de Uso

### Escaneo de un Objetivo Único
```bash
# Usando Docker
docker compose run v-xent --target 8.8.8.8 --shodan --virustotal

# Ejecución Nativa
python3 main.py --target google.com --shodan --virustotal
```

### Escaneo por Lotes (Múltiples Objetivos)
Crea un archivo `targets.txt` con un objetivo por línea:
```bash
python3 main.py --file targets.txt --shodan --virustotal
```

### Integración con SIEM (Logs JSON)
```bash
python3 main.py --target 8.8.8.8 --shodan --virustotal --json-log
```

---

## 📂 Estructura del Proyecto

```text
v-xent/
├── config/             # Gestión de configuración segura (.env)
├── scanners/           # Módulos de Shodan & VirusTotal
├── intel_gathering/    # Correlacionador avanzado de amenazas
├── utils/              # Validador, Crypto (HMAC), Reporter (Jinja2), Logger
├── templates/          # Plantillas seguras de reportes HTML
├── output/             # Reportes persistentes firmados digitalmente
└── main.py             # Punto de entrada seguro (CLI)
```

---

## ⚖️ Ética y Descargo de Responsabilidad

**V-XENT** está destinado únicamente a la investigación ética de seguridad y pruebas de penetración autorizadas. K-VØID Labs y jscamargo-cyber no se hacen responsables del mal uso de esta herramienta. Úsala con responsabilidad.

---

*"La inteligencia es la primera línea de defensa."* - **V-XENT Framework [SECURE]**
**Desarrollado por jscamargo-cyber © 2026**
