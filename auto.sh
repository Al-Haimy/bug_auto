#!/bin/bash
# =====================================================================
# 🔥 Full Bug Bounty Pipeline (Subdomains + Web Recon) with Timeout=5s
# =====================================================================

TARGET_DOMAIN=$1
WORDLIST="/root/tools/lists/subdomains-top1million-5000.txt" # DNS wordlist
SHODAN_KEY=""                # Shodan API key
RESOLVERS="/root/tools/lists/resolvers.txt"                  # Good resolvers

# === Output Directories ===
OUTDIR="scan_results_$(date +%F_%H-%M-%S)"
mkdir -p "$OUTDIR"

SUBS="$OUTDIR/subdomains_all.txt"
RESOLVED="$OUTDIR/subdomains_resolved.txt"
ALIVE="$OUTDIR/alive.txt"
RAW_URLS="$OUTDIR/raw_urls.txt"
FILTERED_URLS="$OUTDIR/urls_for_secretfinder.txt"
JSFILES="$OUTDIR/js_files.txt"
SECRETS="$OUTDIR/secrets_found.txt"
JUICE_OUT="$OUTDIR/juice_secrets.txt"
LINKFINDER_OUT="$OUTDIR/linkfinder_results.txt"
NUCLEI_OUT="$OUTDIR/nuclei_scan_results.txt"
LOG="$OUTDIR/scan.log"
NUCLEI_TEMPLATES="/root/tools/nuclei-tmp"

THREADS=50
TIMEOUT=5
CONCURRENCY=10

echo "[+] Starting Full Recon for $TARGET_DOMAIN at $(date)" | tee -a "$LOG"

# === SUBDOMAIN ENUMERATION ===
echo "[+] [1/13] Running Shodomain..." | tee -a "$LOG"
python3 /root/tools/shoban.py "$TARGET_DOMAIN" > "$OUTDIR/shodan.txt" 2>>"$LOG"

echo "[+] [2/13] Fetching from crt.sh..." | tee -a "$LOG"
curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" \
| jq -r '.[].name_value' | sed 's/\*\.//g' | grep "$TARGET_DOMAIN" | sort -u > "$OUTDIR/crtsh.txt"

# === First Brute Force ===
echo "[+] [3/13] Brute-forcing with puredns on main target..." | tee -a "$LOG"
puredns bruteforce "$WORDLIST" "$TARGET_DOMAIN" --resolvers "$RESOLVERS" --wildcard-tests 3 -q > "$OUTDIR/puredns_cycle0.txt" 2>>"$LOG"

# === Recursive Brute Force: Cycle 1 & 2 ===
CYCLE_INPUT="$OUTDIR/puredns_cycle0.txt"
for CYCLE in 1 2; do
    echo "[+] Running brute force cycle $CYCLE on all found subdomains..." | tee -a "$LOG"
    CYCLE_OUTPUT="$OUTDIR/puredns_cycle${CYCLE}.txt"
    > "$CYCLE_OUTPUT"

    cat "$CYCLE_INPUT" | xargs -P $CONCURRENCY -I {} bash -c \
        "puredns bruteforce \"$WORDLIST\" \"{}\" --resolvers \"$RESOLVERS\" --wildcard-tests 3 -q" \
        >> "$CYCLE_OUTPUT" 2>>"$LOG"

    sort -u "$CYCLE_OUTPUT" -o "$CYCLE_OUTPUT"
    CYCLE_INPUT="$CYCLE_OUTPUT"
done

# === Combine all subdomains ===
echo "[+] [4/13] Combining subdomains and removing duplicates..." | tee -a "$LOG"
cat "$OUTDIR/shodan.txt" "$OUTDIR/crtsh.txt" \
    "$OUTDIR/puredns_cycle0.txt" "$OUTDIR/puredns_cycle1.txt" "$OUTDIR/puredns_cycle2.txt" \
    | sort -u > "$SUBS"

# === Resolution ===
echo "[+] [5/13] Active resolution with dnsx..." | tee -a "$LOG"
dnsx -l "$SUBS" -silent -o "$RESOLVED"

# === WEB RECON ===
echo "[+] [6/13] Probing live web services with httpx..." | tee -a "$LOG"
httpx -l "$RESOLVED" -threads $THREADS -timeout $TIMEOUT -silent -o "$ALIVE"

echo "[+] [7/13] Gathering historical URLs (gau & waybackurls)..." | tee -a "$LOG"
touch "$RAW_URLS"
if command -v gau >/dev/null; then
    cat "$ALIVE" | xargs -P $CONCURRENCY -n 1 bash -c 'timeout 5s gau "$0"' >> "$RAW_URLS" 2>>"$LOG"
fi
if command -v waybackurls >/dev/null; then
    cat "$ALIVE" | xargs -P $CONCURRENCY -n 1 bash -c 'timeout 5s waybackurls "$0"' >> "$RAW_URLS" 2>>"$LOG"
fi

echo "[+] [8/13] Crawling with Katana..." | tee -a "$LOG"
katana -list "$ALIVE" -silent -timeout $TIMEOUT -js-crawl -depth 3 -jc -nc \
    -ef woff,css,png,jpg,jpeg,gif,svg,ico,ttf,mp4,mp3,pdf,zip,rar,tar,gz \
    >> "$RAW_URLS" 2>>"$LOG"

sort -u "$RAW_URLS" -o "$RAW_URLS"

# === FILTER URLS ===
echo "[+] [9/13] Filtering URLs (excluding images/media)..." | tee -a "$LOG"
grep -Ev '\.(woff|woff2|css|png|jpg|jpeg|gif|svg|ico|ttf|eot|mp4|mp3|avi|mov|pdf|zip|tar|gz|rar)($|\?)' "$RAW_URLS" \
| sort -u > "$FILTERED_URLS"

grep -Ei "\.js($|\?)" "$RAW_URLS" | sort -u > "$JSFILES"

# === SECRET SCANNING ===
echo "[+] [10/13] Running SecretFinder on filtered URLs..." | tee -a "$LOG"
cat "$FILTERED_URLS" | xargs -P $CONCURRENCY -n 1 bash -c '
  url="$0"
  echo "[*] SecretFinder scanning $url" >> "'"$LOG"'"
  timeout 5s python3 /root/tools/SecretFinder/SecretFinder.py -i "$url" -o cli >> "'"$SECRETS"'" 2>>"'"$LOG"'"
'

# === JUICE.PY SCANNING ===
echo "[+] [11/13] Running juice.py on filtered URLs..." | tee -a "$LOG"
cat "$FILTERED_URLS" | python3 /root/tools/juice2.py >> $JUICE_OUT

# === LINKFINDER ===
if [ -f /root/tools/LinkFinder/linkfinder.py ]; then
    echo "[+] [12/13] Running LinkFinder on filtered URLs..." | tee -a "$LOG"
    cat "$FILTERED_URLS" | xargs -P $CONCURRENCY -n 1 bash -c '
      url="$0"
      python3 /root/tools/LinkFinder/linkfinder.py -i "$url" -o cli >> "'"$LINKFINDER_OUT"'" 2>>"'"$LOG"'"
    '
fi

# === NUCLEI SCAN ===
echo "[+] [13/13] Running nuclei on alive hosts..." | tee -a "$LOG"
nuclei -l "$ALIVE" -t "$NUCLEI_TEMPLATES" -timeout $TIMEOUT -silent -o "$NUCLEI_OUT"

if [ -s "$LINKFINDER_OUT" ]; then
    sort -u "$LINKFINDER_OUT" > "$OUTDIR/endpoints_for_nuclei.txt"
    echo "[+] Running nuclei on LinkFinder endpoints..." | tee -a "$LOG"
    nuclei -l "$OUTDIR/endpoints_for_nuclei.txt" -t "$NUCLEI_TEMPLATES" -timeout $TIMEOUT -silent -o "$OUTDIR/nuclei_endpoints_results.txt"
fi

echo "[+] Recon Completed at $(date)" | tee -a "$LOG"
echo "[+] Final results saved in: $OUTDIR"
