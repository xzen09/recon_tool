#!/usr/bin/env python3
"""
Automated Reconnaissance Script
Author: Zicada
Description: Script modular para CTFs: Nmap, DNS, Cabeceras HTTP, Banner Grabbing,
             Fuzzer Multihilo, Detección de WAF, Enumeración de Subdominios (crt.sh)
             y Extracción de Enlaces/Comentarios. Interfaz con 'rich' (fallback a ANSI).
"""

import argparse
import json
import random
import re
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures
from datetime import datetime
from typing import Optional

# --------------------------------------------------------------------------
# Interfaz: intenta usar 'rich' para una UI tipo Nuclei/Nmap; si no está
# instalado, cae automáticamente a ANSI plano (el script sigue funcionando
# sin dependencias extra, útil en entornos CTF sin pip).
# --------------------------------------------------------------------------
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
    )
    from rich.text import Text
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# Códigos de color ANSI (fallback)
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD = "\033[1m"


def info(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[cyan][*][/cyan] {msg}")
    else:
        print(f"{CYAN}[*]{RESET} {msg}")


def ok(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[green][+][/green] {msg}")
    else:
        print(f"{GREEN}[+]{RESET} {msg}")


def warn(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[yellow][!][/yellow] {msg}")
    else:
        print(f"{YELLOW}[!]{RESET} {msg}")


def err(msg: str) -> None:
    if RICH_AVAILABLE:
        console.print(f"[red][-][/red] {msg}")
    else:
        print(f"{RED}[-]{RESET} {msg}")


BANNERS = [
    rf"""{CYAN}
    ⠀⠀⢤⡈⠵⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⣍⠆
    ⢠⡙⢦⢌⠱⢩⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⡜⢎
    ⠤⣙⢾⣞⣶⡤⠉⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣧⢛⠆
    ⠠⢍⡞⣿⣿⣿⣧⣄⠢⢈⣙⠻⠿⠛⢟⡯⢻⢿⡻⠞⠌⠃⠈⠀ [{BOLD} Z I C A D A {RESET}{CYAN}]
    ⠡⢎⡸⢽⣿⣿⣿⣯⣿⣿⣯⣶⣶⣿⣿⠧⣆⠦⡐            Reconnaissance Framework
    ⠘⣬⢳⡌⢿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣗⠨⢓⠀            Status: Operational
    ⠈⡒⢯⡽⣂⠻⢿⣿⢧⡛⠿⣯⣿⢿⣷⣟⡦⠁
    ⠀⠈⢣⣛⡵⢆⡀⠉⠛⠽⠲⣌⠻⣿⣿⣿⣿⡄
    ⠀⠀⠠⣙⢾⣱⢎⡔⢡⣀⢁⡀⠄⠈⢻⣿⣿⣷
    ⠀⠀⠀⠈⣽⣻⣾⣜⡦⢤⡉⠄⠀⠀⠀⠈⠻⣿
    ⠀⠀⠀⠀⠐⢿⣽⡾⣝⠣⠈⠀⠀⠀⠀⠀⠀⠈
    ⠀⠀⠀⠀⠀⠀⠙⠙⠈
    {RESET}""",

    rf"""{GREEN}
    ███████╗██╗██╗  ██╗██████╗ ██████╗
    ██╔════╝██║██║  ██║██╔══██╗██╔══██╗  [ {BOLD}Z I C A D A{RESET}{GREEN} ]
    ███████╗██║███████║██████╔╝██████╔╝  Network Discovery Engine
    ╚════██║██║██╔══██║██╔═══╝ ██╔═══╝   Version 2.0-dev
    ███████║██║██║  ██║██║     ██║
    ╚══════╝╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
    {RESET}""",

    rf"""{CYAN}
    ⣿⣿⠟⣁⠤⠒⠉⠁⠀⠀⠀⠀⠀⠂⠂⠙⢿⣿⣿⣿⣿⣿⣿
    ⣿⢣⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿
    ⢧⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⢰⡦⣠⡟⢿⣿⣿⣿
    ⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣼⡟⣿⢇⠸⣿⣿⣿   [{BOLD} Z I C A D A {RESET}{CYAN}]
    ⠃⠀⠀⠀⢀⡄⠀⠀⠀⣄⠀⠀⣰⡄⠀⠀⠑⡹⢦⣄⠀⠀⠉⠛   Automated Recon Engine
    ⠀⠀⠀⠀⢸⣹⡄⣧⡀⢸⠆⠀⠐⢠⠀                          Status: Operational
    ⠀⠀⠀⠀⢘⣿⣿⣿⣧⣿⣧⣴⣄⣠⣇⡀⣦
    ⠀⠀⠀⠀⠘⣿⠟⠉⡻⣿⣿⣿⣿⣿⣿⣿⡟
    ⡄⡀⠀⠀⠀⠉⠀⢤⣄⣹⣿⣿⣿⣿⣿⣿⠃
    ⣧⣷⡠⡀⠀⢀⣄⠀⠙⢿⣿⣿⣿⣿⡿⠃⠀
    ⣿⣿⣷⣿⣦⣾⣿⡀⠀⠀⠀⠀⠀⢉⣴⣶⣤⣀
    ⣿⣿⣿⣿⣿⣿⣿⡇⠀⢠⠀⠀⣴⣿⣿⣿⣿⣿⣿⣶⡄
    ⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⡆⢸⣿⣿⣿⣿⣿⣿⣿⣿⠃
    ⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⡇⠘⣿⣿⣿⣿⣿⣿⣿⡙
    ⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⡇⠀⢹⣿⣿⣿⣿⣿⡏
    {RESET}""",

    rf"""{CYAN}
    ⣿⡿⠿⡇⠄⡺⣿⣿⣷⠐⡋⡿⠟⣿⠆⠌⢂⣰⣿⣷⣦⠄
    ⢠⢳⣥⣼⡀⣮⣠⠞⣄⠆⠊⡘⢶⣟⠆⠄⡐⠋⢻⠞⠛⡁
    ⡝⢟⠻⣿⢿⣆⡭⣾⣇⢀⣬⣉⠬⣷⣷⣦⡙⠶⣉⣱⡖⣯
    ⠁⠈⠃⢣⡿⢸⢄⡨⠟⠇⠄⠄⠈⠉⢆⣨⡿⠄⠻⢏⢀⠋   [{BOLD} Z I C A D A {RESET}{CYAN}]
    ⢁⢲⠶⢮⠛⠓⠙⠆⠄⠠⣤⣤⣄⠠⠚⢋⣨⣄⠄⢀⢶⣿   Reconnaissance Engine
    ⡿⠿⣯⠿⠄⢰⠄⠄⠄⡾⢿⡿⠿⡇⠄⢾⣿⣿⣇⠐⢍⢻   Braille Art Edition
    ⠑⣴⢿⡃⠌⠛⠄⠄⠸⡄⡔⠣⡤⠶⠄⣆⣠⠞⣠⠄⢈⣃
    ⠈⢙⣤⣶⣄⠐⢹⣿⣿⣦⡛⣛⣫⣀⠄⣐⡙⡛⣠⣴⣼⡯
    ⠄⢘⠿⢿⠟⠄⢓⢜⢋⢿⠁⢏⡈⣟⢷⠈⠁⠁⠛⢊⣉⣿
    ⠄⠸⢲⣎⡢⠃⠁⠈⠸⢯⡆⠙⠧⠄⢀⣠⣤⣀⢀⠠⢿⢑
    ⠄⠄⠄⠈⠒⠖⢀⣠⣘⣯⡗⡆⠄⠄⢠⡿⣯⣿⣷⠄⠰⣿
    ⠛⢻⣶⠘⠓⠈⠼⢙⠛⢻⡞⠁⣀⠄⣆⣀⠽⢀⣨⡀⢰⣉
    ⢗⠩⢀⠄⢀⠄⠄⢀⢱⡟⠅⠐⠊⢁⣀⣩⡶⠿⢩⢤⣤⡘
    ⠄⢀⣼⣿⣿⣷⠁⢀⣵⣿⣶⡄⣢⣻⣿⣿⣆⠸⣄⡸⠻
    {RESET}"""
]

DEFAULT_WORDLIST = [
    "admin", "login", "uploads", "api", "backup", "dev", "test", "secret", "config", ".git",
    "robots.txt", "images", "css", "js", "assets", "includes", "lib", "wp-admin", "wp-content",
    "dashboard", "phpmyadmin", "server-status", ".env", "bak", "old", "sql", "db", "administrator",
    "manager", "sitemap.xml", "shell", "cmd", "exec", "source", "hidden", "private", "public",
    "temp", "tmp", "logs", "bin", "cgi-bin", "install", "setup", "portal"
]

# Códigos de estado que consideramos "hallazgo" en el fuzzer (incluye redirects)
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403}

# Firmas de WAF conocidas: (nombre, patrón de cabecera o cuerpo)
WAF_SIGNATURES = [
    ("Cloudflare", {"headers": ["cf-ray", "cf-cache-status", "server:cloudflare"], "body": []}),
    ("AWS WAF / CloudFront", {"headers": ["x-amzn-requestid", "x-amz-cf-id", "server:cloudfront"], "body": []}),
    ("Akamai", {"headers": ["x-akamai-transformed", "akamai-origin-hop"], "body": ["akamai"]}),
    ("Sucuri", {"headers": ["x-sucuri-id", "x-sucuri-cache"], "body": ["sucuri"]}),
    ("Imperva / Incapsula", {"headers": ["x-iinfo", "x-cdn:incapsula"], "body": ["incapsula"]}),
    ("ModSecurity", {"headers": [], "body": ["mod_security", "modsecurity", "this error was logged"]}),
    ("F5 BIG-IP ASM", {"headers": ["x-cnection", "x-wa-info"], "body": ["the requested url was rejected"]}),
    ("Fortinet FortiWeb", {"headers": [], "body": ["fortiweb"]}),
    ("Barracuda", {"headers": ["x-barracuda"], "body": ["barracuda"]}),
]


def banner() -> None:
    art = random.choice(BANNERS)
    if RICH_AVAILABLE:
        console.print(art, highlight=False)
    else:
        print(art)


def draw_progress_bar(iteration: int, total: int, prefix: str = 'Progreso:',
                       suffix: str = 'Completado', length: int = 40) -> None:
    """Barra ANSI de fallback (solo se usa cuando 'rich' no está disponible)."""
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_len = int(length * iteration // total)
    bar = '█' * filled_len + '-' * (length - filled_len)
    sys.stdout.write(f'\r{CYAN}[*]{RESET} {prefix} |{GREEN}{bar}{RESET}| {percent}% {suffix}')
    sys.stdout.flush()
    if iteration == total:
        print()


def normalize_target(raw_target: str) -> tuple:
    """
    Normaliza el target de entrada. Acepta 'ejemplo.com', 'http://ejemplo.com'
    o 'https://ejemplo.com:8443'. Devuelve (hostname, base_url, scheme).
    """
    raw_target = raw_target.strip()
    if "://" not in raw_target:
        raw_target = f"http://{raw_target}"
    parsed = urllib.parse.urlparse(raw_target)
    hostname = parsed.hostname or parsed.netloc
    scheme = parsed.scheme or "http"
    port_part = f":{parsed.port}" if parsed.port else ""
    base_url = f"{scheme}://{hostname}{port_part}"
    return hostname, base_url, scheme


def check_host(hostname: str) -> bool:
    try:
        ip = socket.gethostbyname(hostname)
        ok(f"Objetivo resuelto: {hostname} -> {ip}")
        return True
    except socket.gaierror:
        err(f"No se pudo resolver el host '{hostname}'.")
        return False


def run_nmap(hostname: str, ports: str = "50", timeout: int = 120) -> str:
    info("Iniciando escaneo de puertos (Nmap)...")
    top_ports = ["--top-ports", ports] if ports.isdigit() else ["-p", ports]
    command = ["nmap", "-sV", "-T4", *top_ports, hostname]

    def _run():
        return subprocess.run(
            command, capture_output=True, text=True, errors="replace",
            check=True, timeout=timeout
        )

    try:
        if RICH_AVAILABLE:
            with Progress(
                SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                TimeElapsedColumn(), console=console, transient=True
            ) as progress:
                progress.add_task("Escaneando puertos con nmap...", total=None)
                result = _run()
        else:
            result = _run()
        return result.stdout
    except FileNotFoundError:
        return "__ERROR__:'nmap' no está instalado en el sistema."
    except subprocess.TimeoutExpired:
        return f"__ERROR__:nmap excedió el timeout de {timeout}s."
    except subprocess.CalledProcessError as e:
        return f"__ERROR__:Error al ejecutar nmap: {e.stderr}"


def analyze_http_headers(base_url: str) -> dict:
    info("Analizando cabeceras HTTP...")
    headers_found = {}
    security_headers = ["Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy",
                         "X-Content-Type-Options", "Server"]
    req = urllib.request.Request(base_url, headers={'User-Agent': 'Mozilla/5.0 (Zicada-CTF)'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            resp_headers = dict(response.info())
            final_url = response.geturl()
            if final_url != base_url:
                headers_found["_redirected_to"] = final_url
            for header in security_headers:
                matching_key = next((k for k in resp_headers if k.lower() == header.lower()), None)
                headers_found[header] = resp_headers[matching_key] if matching_key else None
            headers_found["_raw_headers"] = resp_headers
            headers_found["_http_status"] = response.status
    except urllib.error.HTTPError as e:
        resp_headers = dict(e.headers) if e.headers else {}
        for header in security_headers:
            matching_key = next((k for k in resp_headers if k.lower() == header.lower()), None)
            headers_found[header] = resp_headers[matching_key] if matching_key else None
        headers_found["_raw_headers"] = resp_headers
        headers_found["_http_status"] = e.code
    except Exception:
        headers_found["error"] = "Servicio HTTP no disponible."
    return headers_found


def grab_banner_single(hostname: str, port: int, timeout: float = 1.5) -> tuple:
    """Worker: intenta conectar y capturar banner de un solo puerto."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((hostname, port)) == 0:
                if port in (80, 8080, 443):
                    try:
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
                    except OSError:
                        pass
                try:
                    banner_data = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    banner_data = ""
                return str(port), banner_data if banner_data else "Abierto (Sin banner explícito)"
    except Exception:
        pass
    return str(port), None


def grab_banners(hostname: str, max_threads: int = 9) -> dict:
    info("Ejecutando Banner Grabbing en puertos críticos...")
    common_ports = [21, 22, 25, 80, 110, 143, 445, 3306, 8080]
    banners = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futuros = {executor.submit(grab_banner_single, hostname, port): port for port in common_ports}
        for futuro in concurrent.futures.as_completed(futuros):
            port, banner_data = futuro.result()
            if banner_data is not None:
                banners[port] = banner_data
    return banners


def check_directory(base_url: str, word: str) -> tuple:
    """Worker que comprueba un solo directorio/archivo."""
    url = f"{base_url}/{word}"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Zicada-CTF)'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return f"/{word}", response.status
    except urllib.error.HTTPError as e:
        if e.code in INTERESTING_CODES:
            return f"/{word}", e.code
    except Exception:
        pass
    return f"/{word}", None


def load_wordlist(path: Optional[str]) -> list:
    if not path:
        return DEFAULT_WORDLIST
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if not words:
            warn("Wordlist vacía, usando la lista por defecto.")
            return DEFAULT_WORDLIST
        ok(f"Wordlist cargada: {len(words)} palabras desde '{path}'")
        return words
    except IOError as e:
        err(f"No se pudo leer la wordlist '{path}': {e}. Usando la lista por defecto.")
        return DEFAULT_WORDLIST


def internal_fuzzer(base_url: str, wordlist: list, max_threads: int = 15) -> dict:
    """Fuzzer multihilo utilizando ThreadPoolExecutor y actualización dinámica."""
    info(f"Iniciando Fuzzer Web Multihilo ({max_threads} hilos, {len(wordlist)} palabras)...")

    found_dirs = {}
    total_words = len(wordlist)
    completed = 0

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)
    try:
        if RICH_AVAILABLE:
            with Progress(
                TextColumn("[cyan][*][/cyan] Fuzzing"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("•"),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("fuzz", total=total_words)
                futuros = {executor.submit(check_directory, base_url, word): word for word in wordlist}
                for futuro in concurrent.futures.as_completed(futuros):
                    path, status = futuro.result()
                    if status is not None:
                        found_dirs[path] = status
                    completed += 1
                    progress.update(task, completed=completed)
        else:
            draw_progress_bar(completed, total_words)
            futuros = {executor.submit(check_directory, base_url, word): word for word in wordlist}
            for futuro in concurrent.futures.as_completed(futuros):
                path, status = futuro.result()
                if status is not None:
                    found_dirs[path] = status
                completed += 1
                draw_progress_bar(completed, total_words)
    except KeyboardInterrupt:
        warn("Interrumpido por el usuario, cancelando tareas pendientes...")
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        executor.shutdown(wait=True)

    return found_dirs


# --------------------------------------------------------------------------
# Módulo: Detección de WAF
# --------------------------------------------------------------------------
def detect_waf(base_url: str, raw_headers: dict) -> list:
    """
    Compara las cabeceras ya obtenidas y una petición que fuerza un 403/406
    (payload simple tipo XSS en query string) contra firmas conocidas de WAF.
    Devuelve una lista de nombres de WAF detectados (puede estar vacía).
    """
    info("Analizando posible WAF / protección perimetral...")
    detected = set()
    headers_lower = {k.lower(): str(v).lower() for k, v in raw_headers.items()}
    headers_blob = " ".join(f"{k}:{v}" for k, v in headers_lower.items())

    # 1) Firmas por cabecera ya recolectada
    for name, sig in WAF_SIGNATURES:
        for h in sig["headers"]:
            if ":" in h:
                key, val = h.split(":", 1)
                if headers_lower.get(key) and val in headers_lower.get(key, ""):
                    detected.add(name)
            elif h in headers_lower:
                detected.add(name)

    # 2) Petición provocadora: payload simple que suele gatillar bloqueo del WAF
    probe_url = base_url.rstrip("/") + "/?test=<script>alert(1)</script>"
    req = urllib.request.Request(probe_url, headers={'User-Agent': 'Mozilla/5.0 (Zicada-CTF)'})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(4096).decode('utf-8', errors='ignore').lower()
            probe_headers = {k.lower(): str(v).lower() for k, v in dict(resp.info()).items()}
            _match_waf_body_headers(body, probe_headers, detected)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(4096).decode('utf-8', errors='ignore').lower()
        except Exception:
            pass
        probe_headers = {k.lower(): str(v).lower() for k, v in (dict(e.headers) if e.headers else {}).items()}
        _match_waf_body_headers(body, probe_headers, detected)
        if e.code in (403, 406, 419, 429) and not detected:
            detected.add(f"Desconocido (bloqueo HTTP {e.code} ante payload de prueba)")
    except Exception:
        pass

    if detected:
        for name in detected:
            warn(f"Posible WAF detectado: {BOLD if not RICH_AVAILABLE else ''}{name}")
    else:
        ok("No se detectaron firmas de WAF conocidas (no es garantía de ausencia).")

    return sorted(detected)


def _match_waf_body_headers(body: str, headers_lower: dict, detected: set) -> None:
    headers_blob = " ".join(f"{k}:{v}" for k, v in headers_lower.items())
    for name, sig in WAF_SIGNATURES:
        for h in sig["headers"]:
            if ":" in h:
                key, val = h.split(":", 1)
                if headers_lower.get(key) and val in headers_lower.get(key, ""):
                    detected.add(name)
            elif h in headers_lower:
                detected.add(name)
        for needle in sig["body"]:
            if needle in body:
                detected.add(name)


# --------------------------------------------------------------------------
# Módulo: Enumeración pasiva de subdominios vía crt.sh (Certificate Transparency)
# --------------------------------------------------------------------------
def enumerate_subdomains(domain: str, timeout: int = 15) -> list:
    """
    Consulta crt.sh (logs de Certificate Transparency) para listar subdominios
    que alguna vez hayan sido emitidos en un certificado para el dominio.
    100% pasivo: no toca el servidor objetivo en ningún momento.
    """
    info(f"Consultando crt.sh (OSINT pasivo) para subdominios de '{domain}'...")
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Zicada-CTF)'})
    subdomains = set()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode('utf-8', errors='ignore')
            data = json.loads(raw)
            for entry in data:
                name_value = entry.get("name_value", "")
                for line in name_value.split("\n"):
                    line = line.strip().lower()
                    if line and "*" not in line and line.endswith(domain):
                        subdomains.add(line)
    except urllib.error.URLError as e:
        warn(f"No se pudo contactar crt.sh: {e}")
    except json.JSONDecodeError:
        warn("crt.sh devolvió una respuesta vacía o no-JSON (puede estar rate-limiting).")
    except Exception as e:
        warn(f"Error consultando crt.sh: {e}")

    result = sorted(subdomains)
    if result:
        ok(f"{len(result)} subdominio(s) único(s) encontrado(s) en Certificate Transparency.")
    else:
        warn("Sin resultados en crt.sh para este dominio.")
    return result


# --------------------------------------------------------------------------
# Módulo: Extracción de enlaces y comentarios ocultos en el HTML principal
# --------------------------------------------------------------------------
LINK_RE = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''', re.IGNORECASE)
COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)


def extract_links_and_comments(base_url: str, timeout: int = 5) -> dict:
    """
    Descarga la página principal y extrae enlaces (href/src/action) y
    comentarios HTML, que a menudo revelan rutas, APIs o notas de desarrollo.
    """
    info("Extrayendo enlaces y comentarios de la página principal...")
    req = urllib.request.Request(base_url, headers={'User-Agent': 'Mozilla/5.0 (Zicada-CTF)'})
    result = {"links": [], "comments": []}
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            html = response.read(1_000_000).decode('utf-8', errors='ignore')
    except Exception as e:
        warn(f"No se pudo descargar '{base_url}' para extraer enlaces: {e}")
        return result

    links = {m.group(1).strip() for m in LINK_RE.finditer(html)}
    links = {l for l in links if l and not l.startswith("data:") and not l.startswith("javascript:")}
    result["links"] = sorted(links)

    comments = []
    for m in COMMENT_RE.finditer(html):
        text = m.group(1).strip()
        text = re.sub(r'\s+', ' ', text)
        if text and len(text) < 500:
            comments.append(text)
    result["comments"] = comments

    ok(f"{len(result['links'])} enlace(s) y {len(result['comments'])} comentario(s) extraídos.")
    return result


# --------------------------------------------------------------------------
# Presentación de resultados (rich si está disponible, ANSI si no)
# --------------------------------------------------------------------------
def print_summary(http_headers: dict, banners: dict, fuzzed_dirs: dict,
                   waf_detected: list, subdomains: list, links_data: dict) -> None:
    if RICH_AVAILABLE:
        _print_summary_rich(http_headers, banners, fuzzed_dirs, waf_detected, subdomains, links_data)
    else:
        _print_summary_ansi(http_headers, banners, fuzzed_dirs, waf_detected, subdomains, links_data)


def _print_summary_rich(http_headers, banners, fuzzed_dirs, waf_detected, subdomains, links_data) -> None:
    console.rule("[bold cyan]RESUMEN DE DIAGNÓSTICO (CTF)[/bold cyan]")

    if waf_detected:
        waf_text = ", ".join(waf_detected)
        console.print(Panel(f"[bold yellow]{waf_text}[/bold yellow]",
                             title="[bold red]WAF / Protección Detectada[/bold red]", expand=False))
    else:
        console.print(Panel("[green]Sin firmas de WAF conocidas[/green]",
                             title="WAF", expand=False))

    if banners:
        table = Table(title="Banners (Sockets)", show_lines=False)
        table.add_column("Puerto", style="cyan", justify="right")
        table.add_column("Banner / Estado", style="white")
        for port, ban in sorted(banners.items(), key=lambda kv: int(kv[0])):
            short_ban = (ban[:70] + '...') if len(ban) > 70 else ban
            table.add_row(port, short_ban.replace("\n", " "))
        console.print(table)

    table = Table(title="Directorios Descubiertos (Fuzzer Interno)")
    table.add_column("Ruta", style="white")
    table.add_column("HTTP", justify="center")
    if fuzzed_dirs:
        for path, status in fuzzed_dirs.items():
            color = "green" if status in (200, 201, 204) else "yellow"
            table.add_row(path, f"[{color}]{status}[/{color}]")
    else:
        table.add_row("—", "[red]Sin hallazgos[/red]")
    console.print(table)

    if subdomains:
        table = Table(title=f"Subdominios (crt.sh) — {len(subdomains)} encontrados")
        table.add_column("Subdominio", style="cyan")
        for sd in subdomains[:50]:
            table.add_row(sd)
        if len(subdomains) > 50:
            table.add_row(f"... y {len(subdomains) - 50} más (ver reporte JSON/MD)")
        console.print(table)

    if links_data.get("comments"):
        table = Table(title="Comentarios HTML Hallados")
        table.add_column("Comentario", style="yellow")
        for c in links_data["comments"][:15]:
            table.add_row(c[:120])
        console.print(table)

    headers_text = Text()
    if "error" not in http_headers:
        redirected = http_headers.get("_redirected_to")
        if redirected:
            headers_text.append(f"Redirigido a: {redirected}\n", style="yellow")
        server = http_headers.get("Server")
        headers_text.append(f"Servidor: {server if server else 'Oculto'}", style="cyan")
    else:
        headers_text.append(http_headers["error"], style="red")
    console.print(Panel(headers_text, title="Cabeceras HTTP", expand=False))


def _print_summary_ansi(http_headers, banners, fuzzed_dirs, waf_detected, subdomains, links_data) -> None:
    print(f"\n{BOLD}=================== RESUMEN DE DIAGNÓSTICO (CTF) ==================={RESET}")

    print(f"\n{BOLD}[+] WAF / Protección:{RESET}")
    if waf_detected:
        print(f"  {YELLOW}{', '.join(waf_detected)}{RESET}")
    else:
        print(f"  {GREEN}Sin firmas de WAF conocidas{RESET}")

    if banners:
        print(f"\n{BOLD}[+] Banners (Sockets):{RESET}")
        for port, ban in sorted(banners.items(), key=lambda kv: int(kv[0])):
            short_ban = (ban[:60] + '...') if len(ban) > 60 else ban
            print(f"  • Puerto {port}: {CYAN}{short_ban.replace(chr(10), ' ')}{RESET}")

    print(f"\n{BOLD}[+] Directorios Descubiertos (Fuzzer Interno):{RESET}")
    if fuzzed_dirs:
        for path, status in fuzzed_dirs.items():
            color = GREEN if status in (200, 201, 204) else YELLOW
            print(f"  • {path} -> HTTP {color}[{status}]{RESET}")
    else:
        print(f"  {RED}[-] Sin hallazgos.{RESET}")

    if subdomains:
        print(f"\n{BOLD}[+] Subdominios (crt.sh) — {len(subdomains)} encontrados:{RESET}")
        for sd in subdomains[:50]:
            print(f"  • {sd}")
        if len(subdomains) > 50:
            print(f"  ... y {len(subdomains) - 50} más (ver reporte)")

    if links_data.get("comments"):
        print(f"\n{BOLD}[+] Comentarios HTML Hallados:{RESET}")
        for c in links_data["comments"][:15]:
            print(f"  • {YELLOW}{c[:120]}{RESET}")

    print(f"\n{BOLD}[+] Estado de Cabeceras HTTP:{RESET}")
    if "error" not in http_headers:
        redirected = http_headers.get("_redirected_to")
        if redirected:
            print(f"  • {YELLOW}Redirigido a:{RESET} {redirected}")
        server = http_headers.get("Server")
        print(f"  • {BOLD}Servidor:{RESET} {CYAN}{server if server else 'Oculto'}{RESET}")
    else:
        print(f"  {RED}[-] {http_headers['error']}{RESET}")

    print(f"\n{BOLD}===================================================================={RESET}")


def export_reports(hostname: str, nmap_out: str, http_out: dict, banners_out: dict,
                    fuzz_out: dict, waf_out: list, subdomains_out: list,
                    links_out: dict, output_file: str) -> None:
    report_data = {
        "target": hostname,
        "timestamp": datetime.now().isoformat(),
        "waf_detected": waf_out,
        "banners_grabbed": banners_out,
        "directories_found": fuzz_out,
        "subdomains": subdomains_out,
        "links_found": links_out.get("links", []),
        "html_comments": links_out.get("comments", []),
        "http_security_headers": {k: v for k, v in http_out.items() if not k.startswith("_")},
        "nmap_scan": nmap_out
    }
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
    except IOError as e:
        err(f"Error al exportar JSON: {e}")
        return

    md_file = output_file.replace(".json", ".md")
    try:
        with open(md_file, "w", encoding="utf-8") as f:
            f.write(f"# Reporte de Reconocimiento: `{hostname}`\n\n")
            f.write(f"**Fecha de escaneo:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n---\n\n")

            f.write("## 1. Nmap Port Scan\n```text\n")
            f.write(nmap_out.strip() if nmap_out else "Sin resultados.")
            f.write("\n```\n\n")

            f.write("## 2. WAF / Protección Detectada\n")
            f.write(", ".join(waf_out) if waf_out else "Sin firmas de WAF conocidas.")
            f.write("\n\n")

            f.write("## 3. Banner Grabbing\n")
            if banners_out:
                for port, b in banners_out.items():
                    f.write(f"- **Puerto {port}:** `{b}`\n")
            else:
                f.write("Sin hallazgos.\n")
            f.write("\n")

            f.write("## 4. Directorios Encontrados\n")
            if fuzz_out:
                for path, status in fuzz_out.items():
                    f.write(f"- `{path}`: HTTP **{status}**\n")
            else:
                f.write("Sin hallazgos.\n")
            f.write("\n")

            f.write("## 5. Subdominios (crt.sh — OSINT pasivo)\n")
            if subdomains_out:
                for sd in subdomains_out:
                    f.write(f"- `{sd}`\n")
            else:
                f.write("Sin resultados.\n")
            f.write("\n")

            f.write("## 6. Enlaces Extraídos (página principal)\n")
            if links_out.get("links"):
                for l in links_out["links"]:
                    f.write(f"- `{l}`\n")
            else:
                f.write("Sin enlaces extraídos.\n")
            f.write("\n")

            f.write("## 7. Comentarios HTML\n")
            if links_out.get("comments"):
                for c in links_out["comments"]:
                    f.write(f"- `{c}`\n")
            else:
                f.write("Sin comentarios encontrados.\n")
            f.write("\n")

            f.write("## 8. Cabeceras de Seguridad HTTP\n")
            if "error" not in http_out:
                for header, val in http_out.items():
                    if header.startswith("_"):
                        continue
                    f.write(f"- **{header}:** `{val if val else 'No presente'}`\n")
            else:
                f.write(f"{http_out['error']}\n")

        ok(f"Reporte JSON guardado en: {output_file}")
        ok(f"Write-up Markdown generado en: {md_file}")
    except IOError as e:
        err(f"Error al exportar Markdown: {e}")


def main() -> None:
    banner()
    if not RICH_AVAILABLE:
        warn("Librería 'rich' no instalada — usando interfaz ANSI básica. "
             "Instala con: pip install rich --break-system-packages")

    parser = argparse.ArgumentParser(description="Zicada Recon Tool - Standalone & Multithread Edition")
    parser.add_argument("-t", "--target", required=False, help="Dominio u IP objetivo")
    parser.add_argument("-o", "--output", default="recon_report.json", help="Nombre del archivo de salida")
    parser.add_argument("-w", "--workers", type=int, default=15, help="Número de hilos para el fuzzer web (default: 15)")
    parser.add_argument("-p", "--ports", default="50",
                         help="Puertos para nmap: número de top-ports (ej. 50) o rango/lista explícita (ej. 1-1000)")
    parser.add_argument("-W", "--wordlist", default=None, help="Ruta a una wordlist personalizada para el fuzzer")
    parser.add_argument("--https", action="store_true", help="Forzar HTTPS en las fases web si no se especifica esquema")
    parser.add_argument("--nmap-timeout", type=int, default=120, help="Timeout en segundos para nmap (default: 120)")
    parser.add_argument("--skip-nmap", action="store_true", help="Omitir el escaneo de nmap")
    parser.add_argument("--skip-waf", action="store_true", help="Omitir la detección de WAF")
    parser.add_argument("--skip-subdomains", action="store_true", help="Omitir la enumeración de subdominios (crt.sh)")
    parser.add_argument("--skip-links", action="store_true", help="Omitir la extracción de enlaces/comentarios")

    args = parser.parse_args()
    target_input = args.target

    if not target_input:
        if RICH_AVAILABLE:
            target_input = console.input("[bold cyan]Ingresa la IP o dominio objetivo: [/bold cyan]").strip()
        else:
            target_input = input(f"{BOLD}{CYAN}Ingresa la IP o dominio objetivo: {RESET}").strip()
    if not target_input:
        sys.exit(1)

    hostname, base_url, scheme = normalize_target(target_input)
    if args.https and "://" not in target_input:
        base_url = base_url.replace("http://", "https://")

    if not check_host(hostname):
        sys.exit(1)

    try:
        nmap_results = "" if args.skip_nmap else run_nmap(hostname, ports=args.ports, timeout=args.nmap_timeout)
        if nmap_results.startswith("__ERROR__:"):
            err(nmap_results.replace("__ERROR__:", ""))
            nmap_results = ""

        http_results = analyze_http_headers(base_url)
        raw_headers = http_results.get("_raw_headers", {})

        waf_results = [] if args.skip_waf else detect_waf(base_url, raw_headers)

        # Subdominios: solo tiene sentido si target es un dominio, no una IP cruda
        is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname) is not None
        if args.skip_subdomains or is_ip:
            subdomains_results = []
        else:
            subdomains_results = enumerate_subdomains(hostname)

        links_results = {"links": [], "comments": []} if args.skip_links else extract_links_and_comments(base_url)

        banners_results = grab_banners(hostname)
        wordlist = load_wordlist(args.wordlist)
        fuzz_results = internal_fuzzer(base_url, wordlist, max_threads=args.workers)
    except KeyboardInterrupt:
        err("Escaneo cancelado por el usuario.")
        sys.exit(130)

    print_summary(http_results, banners_results, fuzz_results, waf_results, subdomains_results, links_results)
    export_reports(hostname, nmap_results, http_results, banners_results, fuzz_results,
                    waf_results, subdomains_results, links_results, args.output)


if __name__ == "__main__":
    main()