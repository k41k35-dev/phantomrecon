#!/bin/bash
# ┌── FERODIR v17 — High-Speed One-Shot Web Fuzzing Pipeline
# by k41k35 — Offensive Reconnaissance Arsenal
# ferodir <url> [-o log.json]   ←  solo eso, nada más.
#
# CONTRATO (lo usa nmap_engine.py):
#     ferodir <url> -o <archivo.json>

set -o pipefail

# ── Colores ──
if [ -t 1 ]; then
    CY="\x1b[38;5;81m"; GO="\x1b[38;5;220m"; GR="\x1b[38;5;112m"
    RD="\x1b[38;5;196m"; MG="\x1b[38;5;213m"; OR="\x1b[38;5;208m"
    GY="\x1b[38;5;245m"; BD="\x1b[1m"; RS="\x1b[0m"
else
    CY=""; GO=""; GR=""; RD=""; MG=""; OR=""; GY=""; BD=""; RS=""
fi

say() { printf "%b\n" "$1"; }
die() { printf "%b\n" "${RD}[!] $1${RS}" >&2; exit 1; }

# ── Args: solo URL + -o ──
URL=""; LOG_FILE="./ferox_scan.json"; THREADS=200
while [[ $# -gt 0 ]]; do
  case $1 in
    -t|--threads) THREADS="$2"; shift 2 ;;
    -o|--output) LOG_FILE="$2"; shift 2 ;;
    -h|--help)   say "${CY}ferodir ${GO}<url>${RS} [-o log.json] [-t threads]"; exit 0 ;;
    -*) shift ;;
    *)  [ -z "$URL" ] && URL="$1"; shift ;;
  esac
done

[ -z "$URL" ] && die "Uso: ferodir <url> [-o log.json]"
[[ "$URL" != http://* && "$URL" != https://* ]] && URL="http://${URL}"
command -v feroxbuster >/dev/null 2>&1 || die "feroxbuster no instalado. brew install feroxbuster"

HAS_JQ=false; command -v jq >/dev/null 2>&1 && HAS_JQ=true
LOG_DIR=$(dirname "$LOG_FILE")
[ -d "$LOG_DIR" ] || mkdir -p "$LOG_DIR" 2>/dev/null

# ── Wordlist ──
WL=""
SEARCH_DIRS=(
    "$SECLISTS"
    "${SECLISTS_DIR:-}"
    "/opt/homebrew/share/seclists"
    "/usr/share/seclists"
    "/usr/share/wordlists/seclists"
    "/usr/share/wordlists/SecLists"
    "$HOME/seclists"
    "$HOME/SecLists"
    "$HOME/wordlists/seclists"
    "${HTB_BASE:-$HOME/HTB}/wordlists/seclists"
)
# Orden de preferencia: directory-list-medium > raft-small > common
for wl_name in directory-list-2.3-medium.txt DirBuster-2007_directory-list-2.3-medium.txt raft-small-words.txt common.txt; do
    [ -n "$WL" ] && break
    for base in "${SEARCH_DIRS[@]}"; do
        [ -n "$base" ] && [ -f "$base/Discovery/Web-Content/$wl_name" ] && { WL="$base/Discovery/Web-Content/$wl_name"; break; }
    done
done
[ -z "$WL" ] && die "No encuentro wordlist. Exporta \$SECLISTS o instala seclists."

# ════════════════════════════════════════════════════════════════════════
#  PRE-SCAN: conectividad + tech detect + soft-404 (todo en paralelo)
# ════════════════════════════════════════════════════════════════════════
T0=$(date +%s)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/ferodir.XXXXXX"); trap 'rm -rf "$TMP"' EXIT
RAND=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 12)

curl -sk -o /dev/null -w "%{http_code}" -m 6 "$URL"                  > "$TMP/st"  2>/dev/null &
curl -skI -m 6 "$URL"                                                > "$TMP/hdr" 2>/dev/null &
curl -sL  -m 6 "$URL" 2>/dev/null | head -c 30000                   > "$TMP/body" &
curl -sk -o /dev/null -w "%{http_code}" -m 5 "${URL%/}/$RAND"       > "$TMP/404" 2>/dev/null &
wait

ST=$(cat "$TMP/st" 2>/dev/null); HDR=$(cat "$TMP/hdr" 2>/dev/null)
BODY=$(cat "$TMP/body" 2>/dev/null); S404=$(cat "$TMP/404" 2>/dev/null)

say "${CY}┌──(${GO}${BD}ferodir${RS}${CY}) v17 — CTF One-Shot${RS}"
if [ -z "$ST" ] || [ "$ST" = "000" ]; then
    say "└─╼ ${RD}⚠ Objetivo no responde. Continuo igual...${RS}"
else
    printf "└─╼ ${GR}Alive:${RS} HTTP %s\n" "$ST"
fi

# ── Tech detect → extensiones ──
EXTS="php,html,txt,bak"
TECH=""
if   echo "$HDR$BODY" | grep -qi 'X-Powered-By:.*PHP\|PHPSESSID\|\.php\|wp-content\|Joomla'; then
    TECH="PHP";         EXTS="php,phtml,inc,txt,bak,zip,html,xml,config"
elif echo "$HDR$BODY" | grep -qi 'ASP.NET\|X-AspNet\|__VIEWSTATE'; then
    TECH="ASP.NET";     EXTS="aspx,asp,config,txt,bak,html"
elif echo "$HDR$BODY" | grep -qi 'JSESSIONID\|Tomcat\|Servlet'; then
    TECH="Java/Tomcat"; EXTS="jsp,do,action,txt,bak,html,xml,war"
elif echo "$HDR$BODY" | grep -qi 'Express\|connect.sid\|__next\|data-reactroot'; then
    TECH="Node.js";     EXTS="js,json,txt,html,bak"
elif echo "$HDR$BODY" | grep -qi 'Werkzeug\|Django\|Python\|csrftoken'; then
    TECH="Python";      EXTS="py,txt,html,bak,json,yaml"
fi

[ -n "$TECH" ] && printf "└─╼ ${GR}Tech:${RS} %s → exts adaptadas\n" "$TECH"

# ── Soft-404 ──
SIMILAR_FLAG=()
case "$S404" in 200|301|302)
    printf "└─╼ ${OR}⚠ Wildcard %s (soft-404) → filtro activo${RS}\n" "$S404"
    SIMILAR_FLAG=(--filter-similar-to "${URL%/}/$RAND")
;; esac

WL_LINES=$(wc -l < "$WL" 2>/dev/null | tr -d ' ')
EXT_N=$(echo "$EXTS" | tr ',' '\n' | wc -l | tr -d ' ')
printf "└─╼ ${GO}Wordlist:${RS} %s ${GY}(%s)${RS}\n" "$(basename "$WL")" "$WL_LINES"
printf "└─╼ ${GO}Exts:${RS} %s\n" "$EXTS"
printf "└─╼ ${GO}Threads:${RS} %s  ${GO}Depth:${RS} 2  ${GO}Est:${RS} ~%s req\n\n" "$THREADS" "$(( WL_LINES * (EXT_N + 1) ))"

# ════════════════════════════════════════════════════════════════════════
#  FEROXBUSTER
# ════════════════════════════════════════════════════════════════════════
feroxbuster \
    -u "$URL" \
    -w "$WL" \
    -x "$EXTS" \
    -t "$THREADS" \
    --depth 2 \
    --auto-tune \
    --insecure \
    --random-agent \
    --dont-scan "/icons/,/assets/images/,/assets/fonts/,/node_modules/,/vendor/,/bower_components/,/static/css/,/static/js/,/static/fonts/" \
    --filter-status 404,400,500,501,502,503,504 \
    --json \
    -o "$LOG_FILE" \
    "${SIMILAR_FLAG[@]}"
RC=$?

# ════════════════════════════════════════════════════════════════════════
#  RESUMEN (single-pass)
# ════════════════════════════════════════════════════════════════════════
T1=$(date +%s); EL=$(( T1 - T0 ))
printf "\n${GY}─────────────────────────────────────────${RS}\n"
printf "${CY}⏱ %dm %ds${RS}  ${GY}(rc=%d)${RS}\n" "$(( EL/60 ))" "$(( EL%60 ))" "$RC"

[ ! -s "$LOG_FILE" ] && { say "${RD}Sin resultados.${RS}"; exit "$RC"; }

if [ "$HAS_JQ" = true ]; then
    DATA=$(jq -r 'select(.type=="response") | "\(.status)\t\(.content_length // 0)\t\(.url)"' "$LOG_FILE" 2>/dev/null)
    for code in 200 204 301 302 307 401 403 405 500; do
        N=$(echo "$DATA" | cut -f1 | grep -c "^${code}$")
        [ "$N" -gt 0 ] && printf "${CY}│${RS} %s: %s\n" "$code" "$N"
    done
    URLS=$(echo "$DATA" | cut -f3 | sort -u)
else
    URLS=$(grep -oE '"url":"[^"]+' "$LOG_FILE" 2>/dev/null | sed 's/"url":"//' | sort -u)
fi

# ── Hallazgos jugosos ──
JUICY=$(echo "$URLS" | grep -iE 'admin|login|dashboard|panel|\.git|\.svn|backup|\.bak|\.old|\.zip|\.tar|\.sql|\.db|dump|\.env|config|secret|password|/api|swagger|graphql|upload|/cgi-bin|\.htaccess|\.htpasswd|robots\.txt|wp-admin|wp-login|console|actuator|server-status|\.key|\.pem|id_rsa' 2>/dev/null)
if [ -n "$JUICY" ]; then
    say "\n${CY}┌──(${RD}${BD}🔥 JUICY${RS}${CY})${RS}"
    while IFS= read -r u; do [ -n "$u" ] && printf "│ ${MG}➜ %s${RS}\n" "$u"; done <<< "$JUICY"
    say "${CY}└──────────────────────${RS}"
fi

# ── Outliers de tamaño ──
if [ "$HAS_JQ" = true ] && [ -n "$DATA" ]; then
    OL=$(echo "$DATA" | awk -F'\t' '$2~/^[0-9]+$/{s[NR]=$2;u[NR]=$3;t+=$2;n++}END{if(n<3)exit;a=t/n;for(i=1;i<=NR;i++)if(i in s&&(s[i]<a/10||s[i]>a*3))printf "%dB\t%s\n",s[i],u[i]}')
    if [ -n "$OL" ]; then
        say "\n${CY}┌──(${MG}⚠ size outliers${CY})${RS}"
        while IFS=$'\t' read -r sz u; do printf "│ ${MG}%-10s → %s${RS}\n" "$sz" "$u"; done <<< "$OL"
        say "${CY}└──────────────────────${RS}"
    fi
fi

# ── Next steps ──
has() { echo "$URLS" | grep -qiE "$1"; }
say "\n${CY}┌──(${GO}${BD}next${RS}${CY})${RS}"
has 'wp-content|wp-admin'       && say "│ 🔵 ${GO}wpscan --url $URL -e u,p,t,vp${RS}"
has '\.git/'                    && say "│ ⚫ ${GO}git-dumper $URL/.git/ ./git_dump${RS}"
has '\.env'                     && say "│ 🔴 ${GO}curl -sk $URL/.env${RS}"
has '/api|swagger|graphql'      && say "│ 🟡 ${GO}Explora la API manualmente${RS}"
has '/cgi-bin'                  && say "│ 🟠 ${GO}Prueba shellshock en /cgi-bin/${RS}"
has 'upload'                    && say "│ 🟢 ${GO}Prueba webshell upload${RS}"
has 'backup|\.bak|\.old|\.zip'  && say "│ 🟤 ${GO}Descarga los backups con curl -O${RS}"
has 'robots\.txt'               && say "│ 📄 ${GO}curl -sk $URL/robots.txt${RS}"
say "${CY}└──────────────────────${RS}"

# ── Web inspector (si existe) ──
WI_CANDIDATES=(
    "${WEB_INSPECTOR_PATH:-}"
    "$(dirname "$0")/web_inspector.py"
    "$(dirname "$0")/../bin/web_inspector.py"
    "$(dirname "$0")/../modules/web_inspector.py"
)
WI=""
for cand in "${WI_CANDIDATES[@]}"; do
    [ -n "$cand" ] && [ -f "$cand" ] && { WI="$cand"; break; }
done
[ -f "$WI" ] && { say "\n${CY}└─╼ ${GO}web_inspector${RS}"; python3 "$WI" "$LOG_FILE"; }

exit "$RC"
