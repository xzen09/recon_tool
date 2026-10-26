# 🕷️ Zicada Recon Tool v2.0

Un framework de reconocimiento automatizado, ligero y multihilo escrito en Python. Diseñado específicamente para entornos de auditoría locales, CTFs (TryHackMe, Hack The Box) y evaluaciones iniciales de superficie de ataque. 

Zicada Recon automatiza fases críticas del *Information Gathering* integrando una interfaz visual avanzada (UI) sin sacrificar la compatibilidad.

## 🚀 Características Principales

* **Interfaz UI Avanzada:** Desarrollada con la librería `rich` (paneles, tablas y barras de progreso fluidas). Incluye *fallback* automático a consola ANSI si se ejecuta en entornos restringidos.
* **Detección de WAF:** Identificación de protecciones perimetrales (Cloudflare, Akamai, AWS WAF, ModSecurity, etc.) mediante firmas en cabeceras y provocación de bloqueos.
* **Enumeración OSINT Pasiva (`crt.sh`):** Descubrimiento sigiloso de subdominios históricos analizando logs de Certificate Transparency sin tocar la infraestructura del cliente.
* **Fuzzer Web Multihilo:** Búsqueda ultrarrápida de directorios ocultos y archivos sensibles. Incluye wordlist optimizada para CTFs y soporte para diccionarios personalizados.
* **Extracción de Enlaces y Comentarios:** Web scraping nativo para revelar rutas de APIs, código comentado o recursos expuestos en el HTML principal.
* **Banner Grabbing TCP:** Conexión por sockets para revelar versiones exactas de servicios en puertos críticos (21, 22, 25, 445, etc.).
* **Generador de Write-Ups:** Exportación dual automática. Genera un reporte detallado en `JSON` y un archivo `Markdown` listo para copiar y pegar en GitHub o Notion.

## 📋 Prerrequisitos

1. **Python 3.x**
2. **Librería Rich:** Para la interfaz visual avanzada.
   ```bash
   pip install rich
   Nmap: (Opcional, pero recomendado). Debe estar agregado al PATH del sistema.

En Windows: winget install Insecure.Nmap

En Linux: sudo apt install nmap

⚙️ Instalación
Clona el repositorio en tu máquina local:

Bash
git clone [https://github.com/TU-USUARIO/recon-tool.git](https://github.com/TU-USUARIO/recon-tool.git)
cd recon-tool

🎯 Uso
Ejecuta la herramienta sin argumentos para entrar en el modo guiado interactivo:

Bash
python recon_tool.py
Ejemplos Avanzados de Ejecución
Bash
# Escaneo rápido usando 30 hilos para el fuzzer
python recon_tool.py -t scanme.nmap.org -w 30

# Escaneo sigiloso (omite Nmap y WAF, ideal para evadir alertas ruidosas)
python recon_tool.py -t 10.10.10.5 --skip-nmap --skip-waf

# Escaneo con un diccionario externo masivo y puertos específicos
python recon_tool.py -t ejemplo.com -W C:\SecLists\common.txt -p 1-1000

| Flag | Descripción |
| :--- | :--- |
| `-t`, `--target` | Dominio o dirección IP objetivo. |
| `-o`, `--output` | Nombre del archivo de exportación (Generará `.json` y `.md`). |
| `-w`, `--workers` | Número de hilos simultáneos para el fuzzer (Default: 15). |
| `-p`, `--ports` | Puertos a escanear con Nmap (Default: 50 top ports). |
| `-W`, `--wordlist` | Ruta absoluta a una wordlist personalizada (`.txt`). |
| `--https` | Fuerza el esquema HTTPS en las fases web. |
| `--skip-nmap` | Omite la fase de escaneo de puertos. |
| `--skip-waf` | Omite la detección y provocación del firewall web. |
| `--skip-subdomains` | Omite la búsqueda OSINT en crt.sh. |
| `--skip-links` | Omite el scraping de comentarios y enlaces del frontend. |

# ⚠️ Aviso Legal
Esta herramienta ha sido desarrollada estrictamente para propósitos educativos, auditorías autorizadas y laboratorios de pruebas (CTF). El uso de este script contra infraestructuras ajenas sin consentimiento explícito es ilegal.


---
