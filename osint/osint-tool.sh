#!/bin/bash
# Universal OSINT Tool (Phone Numbers + Websites + Subdomains + Optional Shodan)
# Generates Text, HTML & PDF Reports + CSV/Excel exports
# Now includes Shodan CSV export (ports, services, vulns)

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
NC="\e[0m"

SHODAN_KEY=""

# --- Parse args ---
if [[ "$1" == "--shodan" ]]; then
    if [ -z "$2" ] || [ -z "$3" ]; then
        echo -e "${RED}[!] Usage: $0 --shodan <API_KEY> <target>${NC}"
        exit 1
    fi
    SHODAN_KEY="$2"
    TARGET="$3"
else
    TARGET="$1"
fi

if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] Usage: $0 [--shodan API_KEY] <phone_number | website_url>${NC}"
    exit 1
fi

TYPE="unknown"
IP=""
CARRIER=""
REGION=""
SUMMARY_SUBDOMAINS=0
SUMMARY_DORKS=0
SUMMARY_SHODAN="Not Used"

# --- Clean filenames ---
if [[ $TARGET =~ ^https?:// ]]; then
    DOMAIN=$(echo $TARGET | sed -E 's~https?://~~;s~/.*~~')
    CLEAN=$DOMAIN
elif [[ $TARGET =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    DOMAIN=$TARGET
    CLEAN=$DOMAIN
else
    CLEAN=$(echo $TARGET | tr -d '+')
fi

REPORT_TXT="report_${CLEAN}.txt"
REPORT_HTML="report_${CLEAN}.html"
REPORT_PDF="report_${CLEAN}.pdf"
REPORT_SUMMARY_CSV="report_summary.csv"
REPORT_SUBDOMAINS_CSV="report_subdomains.csv"
REPORT_SHODAN_CSV="report_shodan.csv"

echo -e "${YELLOW}[i] Target: $TARGET${NC}"

# --- Setup ---
echo -e "${YELLOW}[i] Checking dependencies...${NC}"
sudo apt update -y >/dev/null 2>&1
sudo apt install -y python3 python3-pip git curl jq whois nmap whatweb wkhtmltopdf chromium-browser golang >/dev/null 2>&1
pip3 install --quiet phonenumbers holehe maigret shot-scraper shodan

# Install assetfinder if missing
if ! command -v assetfinder &>/dev/null; then
    echo -e "${YELLOW}[i] Installing assetfinder...${NC}"
    go install github.com/tomnomnom/assetfinder@latest
    export PATH=$PATH:$(go env GOPATH)/bin
fi

mkdir -p tmp_osint/screenshots
> tmp_osint/output.txt
> tmp_osint/dorks.txt
> tmp_osint/subdomains.txt
> $REPORT_SHODAN_CSV

# --- Phone Flow ---
if [[ $TARGET =~ ^\+?[0-9]+$ ]]; then
    TYPE="phone"
    echo -e "${GREEN}[+] Running Carrier Lookup...${NC}"
    echo "===== Carrier Info =====" > tmp_osint/output.txt
    python3 - <<EOF >> tmp_osint/output.txt
import phonenumbers
from phonenumbers import geocoder, carrier
number = phonenumbers.parse("$TARGET")
print("Country/Region:", geocoder.description_for_number(number, "en"))
print("Carrier:", carrier.name_for_number(number, "en"))
EOF
    REGION=$(grep "Country/Region" tmp_osint/output.txt | cut -d':' -f2- | xargs)
    CARRIER=$(grep "Carrier" tmp_osint/output.txt | cut -d':' -f2- | xargs)

    echo -e "${GREEN}[+] Running PhoneInfoga...${NC}"
    if [ ! -d "phoneinfoga" ]; then
        git clone https://github.com/sundowndev/phoneinfoga >/dev/null 2>&1
        cd phoneinfoga && python3 -m pip install -r requirements.txt >/dev/null 2>&1 && cd ..
    fi
    echo -e "\n===== PhoneInfoga =====" >> tmp_osint/output.txt
    python3 phoneinfoga/phoneinfoga.py scan -n "$TARGET" >> tmp_osint/output.txt 2>/dev/null

    echo -e "${GREEN}[+] Running Sherlock...${NC}"
    if [ ! -d "sherlock" ]; then
        git clone https://github.com/sherlock-project/sherlock >/dev/null 2>&1
    fi
    echo -e "\n===== Sherlock =====" >> tmp_osint/output.txt
    python3 sherlock/sherlock.py "$TARGET" --print-found >> tmp_osint/output.txt 2>/dev/null

    echo -e "${GREEN}[+] Running Holehe...${NC}"
    echo -e "\n===== Holehe =====" >> tmp_osint/output.txt
    holehe "$TARGET" >> tmp_osint/output.txt 2>/dev/null

    echo -e "${GREEN}[+] Running Maigret...${NC}"
    echo -e "\n===== Maigret =====" >> tmp_osint/output.txt
    maigret "$TARGET" --json tmp_osint/maigret.json >/dev/null 2>&1
    echo "JSON saved: tmp_osint/maigret.json" >> tmp_osint/output.txt

# --- Website Flow ---
elif [[ $TARGET =~ ^https?:// || $TARGET =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    TYPE="website"
    DOMAIN=$(echo $TARGET | sed -E 's~https?://~~;s~/.*~~')

    echo -e "${GREEN}[+] Running WHOIS...${NC}"
    echo "===== WHOIS =====" > tmp_osint/output.txt
    whois $DOMAIN | head -n 50 >> tmp_osint/output.txt

    echo -e "${GREEN}[+] Checking DNS...${NC}"
    echo -e "\n===== DNS Info =====" >> tmp_osint/output.txt
    IP=$(dig +short A $DOMAIN | head -n1)
    echo "IP Address: $IP" >> tmp_osint/output.txt
    dig +short MX $DOMAIN >> tmp_osint/output.txt
    dig +short NS $DOMAIN >> tmp_osint/output.txt

    echo -e "${GREEN}[+] Running Nmap...${NC}"
    echo -e "\n===== Nmap Top Ports =====" >> tmp_osint/output.txt
    nmap -F $DOMAIN >> tmp_osint/output.txt

    echo -e "${GREEN}[+] Fetching SSL cert...${NC}"
    echo -e "\n===== SSL Certificate =====" >> tmp_osint/output.txt
    echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>/dev/null | openssl x509 -noout -issuer -subject -dates >> tmp_osint/output.txt

    echo -e "${GREEN}[+] Detecting technologies...${NC}"
    echo -e "\n===== Technologies (WhatWeb) =====" >> tmp_osint/output.txt
    whatweb $DOMAIN >> tmp_osint/output.txt

    echo -e "${GREEN}[+] Fetching HTTP headers...${NC}"
    echo -e "\n===== HTTP Headers =====" >> tmp_osint/output.txt
    curl -I -s $DOMAIN >> tmp_osint/output.txt

    echo -e "${GREEN}[+] Capturing screenshot...${NC}"
    echo -e "\n===== Screenshot =====" >> tmp_osint/output.txt
    shot-scraper $DOMAIN --output tmp_osint/screenshots/${DOMAIN}.png >/dev/null 2>&1

    echo -e "${GREEN}[+] Enumerating subdomains...${NC}"
    echo -e "\n===== Subdomains =====" >> tmp_osint/output.txt
    assetfinder --subs-only $DOMAIN | tee tmp_osint/subdomains.txt >> tmp_osint/output.txt
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sort -u | tee -a tmp_osint/subdomains.txt >> tmp_osint/output.txt
    SUMMARY_SUBDOMAINS=$(wc -l < tmp_osint/subdomains.txt)

    # Generate subdomain CSV
    echo "Subdomain,IP" > $REPORT_SUBDOMAINS_CSV
    while read sub; do
        sub_ip=$(dig +short A $sub | head -n1)
        echo "$sub,$sub_ip" >> $REPORT_SUBDOMAINS_CSV
    done < tmp_osint/subdomains.txt

    echo -e "${GREEN}[+] Capturing subdomain screenshots...${NC}"
    for sub in $(head -n 5 tmp_osint/subdomains.txt); do
        safe=$(echo $sub | sed 's/[^a-zA-Z0-9]/_/g')
        shot-scraper $sub --output tmp_osint/screenshots/${safe}.png >/dev/null 2>&1
    done

    if [ ! -z "$SHODAN_KEY" ] && [ ! -z "$IP" ]; then
        echo -e "${GREEN}[+] Fetching Shodan...${NC}"
        echo -e "\n===== Shodan Info =====" >> tmp_osint/output.txt
        shodan_data=$(curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_KEY")
        echo "$shodan_data" | jq '.' >> tmp_osint/output.txt
        SUMMARY_SHODAN="Used"

        # Export Shodan CSV
        echo "Host,IP,Port,Service,Product,Organization,Country,Vulnerabilities" > $REPORT_SHODAN_CSV
        echo "$shodan_data" | jq -r --arg ip "$IP" \
            '.data[]? | [$hostnames[0], $ip, .port, .transport, .product, .org, .location.country_name, (try .vulns | keys | join(";") // "")] | @csv' \
            >> $REPORT_SHODAN_CSV
    fi

    echo -e "${GREEN}[+] Running Dorks...${NC}"
    echo -e "\n===== Google/Bing Dorks =====" >> tmp_osint/output.txt
    QUERIES=(
        "site:$DOMAIN"
        "site:pastebin.com $DOMAIN"
        "site:github.com $DOMAIN"
        "site:stackoverflow.com $DOMAIN"
        "\"$DOMAIN\""
    )
    for q in "${QUERIES[@]}"; do
        enc=$(echo $q | sed 's/ /+/g')
        echo "[Dork] $q" >> tmp_osint/output.txt
        curl -s "https://www.startpage.com/sp/search?q=$enc" \
        | grep -oP 'href="https?://[^"]+' \
        | cut -d'"' -f2 \
        | grep -Ev "startpage|gstatic|google" \
        | tee -a tmp_osint/dorks.txt >> tmp_osint/output.txt
        echo "" >> tmp_osint/output.txt
    done
    SUMMARY_DORKS=$(wc -l < tmp_osint/dorks.txt)
else
    echo -e "${RED}[!] Could not detect input type${NC}"
    exit 1
fi

# --- Save Summary CSV ---
echo "Target,Type,IP,Region,Carrier,Subdomains,Dorks,Shodan" > $REPORT_SUMMARY_CSV
echo "$TARGET,$TYPE,$IP,$REGION,$CARRIER,$SUMMARY_SUBDOMAINS,$SUMMARY_DORKS,$SUMMARY_SHODAN" >> $REPORT_SUMMARY_CSV

# --- Save TXT ---
cp tmp_osint/output.txt $REPORT_TXT

# --- Generate HTML ---
cat > $REPORT_HTML <<EOF
<!DOCTYPE html>
<html>
<head>
<title>OSINT Report for $TARGET</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: #f9f9f9; color: #111; }
.dark { background: #121212; color: #ddd; }
h1 { text-align: center; }
details { margin-bottom: 10px; border: 1px solid #ccc; border-radius: 6px; padding: 8px; background: #fff; }
.dark details { background: #1e1e1e; border-color: #444; }
summary { font-weight: bold; cursor: pointer; }
pre { white-space: pre-wrap; word-wrap: break-word; }
a { color: #0077cc; text-decoration: none; }
a:hover { text-decoration: underline; }
button { position: fixed; top: 10px; right: 10px; padding: 6px 12px; background: #333; color: #fff; border: none; border-radius: 5px; cursor: pointer; }
table { border-collapse: collapse; margin: 10px 0; }
td, th { border: 1px solid #888; padding: 6px 10px; }
</style>
</head>
<body>
<button onclick="document.body.classList.toggle('dark')">🌙 Toggle Dark Mode</button>
<h1>📊 OSINT Report for $TARGET</h1>
<p>Generated on $(date)</p>

<h2>🔎 Summary</h2>
<table>
<tr><th>Type</th><td>$TYPE</td></tr>
EOF

if [ "$TYPE" == "phone" ]; then
    echo "<tr><th>Region</th><td>$REGION</td></tr><tr><th>Carrier</th><td>$CARRIER</td></tr>" >> $REPORT_HTML
elif [ "$TYPE" == "website" ]; then
    echo "<tr><th>IP</th><td>$IP</td></tr><tr><th>Subdomains</th><td>$SUMMARY_SUBDOMAINS</td></tr><tr><th>Dorks</th><td>$SUMMARY_DORKS</td></tr><tr><th>Shodan</th><td>$SUMMARY_SHODAN</td></tr>" >> $REPORT_HTML
fi

cat >> $REPORT_HTML <<EOF
</table>
<details open><summary>Results</summary><pre>$(cat tmp_osint/output.txt)</pre></details>
EOF

if [ "$TYPE" == "website" ]; then
    if [ -f tmp_osint/screenshots/${DOMAIN}.png ]; then
        echo "<details><summary>Main Site Screenshot</summary><img src=\"tmp_osint/screenshots/${DOMAIN}.png\"></details>" >> $REPORT_HTML
    fi
    if [ -s tmp_osint/subdomains.txt ]; then
        echo "<details><summary>Subdomain Screenshots</summary>" >> $REPORT_HTML
        for img in tmp_osint/screenshots/*.png; do
            [ -f "$img" ] && echo "<img src=\"$img\">" >> $REPORT_HTML
        done
        echo "</details>" >> $REPORT_HTML
    fi
    if [ -s tmp_osint/dorks.txt ]; then
        echo "<details><summary>Google/Bing Dorks</summary><ul>" >> $REPORT_HTML
        while read -r line; do
            echo "<li><a href=\"$line\" target=\"_blank\">$line</a></li>" >> $REPORT_HTML
        done < tmp_osint/dorks.txt
        echo "</ul></details>" >> $REPORT_HTML
    fi
    if [ "$SUMMARY_SHODAN" == "Used" ] && [ -s $REPORT_SHODAN_CSV ]; then
        echo "<details><summary>Shodan CSV Export</summary><p>See <code>$REPORT_SHODAN_CSV</code></p></details>" >> $REPORT_HTML
    fi
fi

if [ "$TYPE" == "phone" ]; then
    echo "<details><summary>Maigret JSON</summary><p>Saved at <code>tmp_osint/maigret.json</code></p></details>" >> $REPORT_HTML
fi

echo "</body></html>" >> $REPORT_HTML

# --- Export PDF ---
echo -e "${GREEN}[+] Generating PDF...${NC}"
wkhtmltopdf $REPORT_HTML $REPORT_PDF >/dev/null 2>&1

# --- Done ---
echo -e "${GREEN}[✓] OSINT completed.${NC}"
echo -e "${GREEN}[+] Text: $REPORT_TXT${NC}"
echo -e "${GREEN}[+] HTML: $REPORT_HTML${NC}"
echo -e "${GREEN}[+] PDF: $REPORT_PDF${NC}"
echo -e "${GREEN}[+] Summary CSV: $REPORT_SUMMARY_CSV${NC}"
if [ "$TYPE" == "website" ]; then
    echo -e "${GREEN}[+] Subdomains CSV: $REPORT_SUBDOMAINS_CSV${NC}"
    if [ "$SUMMARY_SHODAN" == "Used" ]; then
        echo -e "${GREEN}[+] Shodan CSV: $REPORT_SHODAN_CSV${NC}"
    fi
fi

# --- Auto Open ---
if command -v xdg-open >/dev/null; then
    echo -e "${GREEN}[+] Opening reports...${NC}"
    xdg-open "$REPORT_HTML" >/dev/null 2>&1 &
    xdg-open "$REPORT_PDF" >/dev/null 2>&1 &
fi
