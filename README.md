# 🔍 OSINT Tool for Linux

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Shell](https://img.shields.io/badge/made%20with-Bash-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)

A **universal OSINT toolkit** that runs on Linux and collects information from **phone numbers** 📱 and **websites** 🌐.  
Generates **HTML, PDF, TXT, CSV reports** with screenshots, dark mode, and optional **Shodan integration**.

---

## ⚡ Features

- 📱 **Phone Number OSINT**
  - Carrier & Region (via `phonenumbers`)
  - PhoneInfoga lookup
  - Sherlock (social media profiles)
  - Holehe (email leaks)
  - Maigret (account discovery)

- 🌐 **Website OSINT**
  - WHOIS lookup
  - DNS records (A, MX, NS)
  - Nmap (top ports)
  - SSL certificate info
  - Technology fingerprinting (WhatWeb)
  - HTTP headers
  - Screenshots (main site + subdomains)
  - Subdomain enumeration (`assetfinder`, `crt.sh`)
  - Google/Bing dorking

- 🔑 **Optional Shodan Integration**
  - Fetch host details, open ports, services, vulnerabilities
  - Export results into CSV

- 📂 **Reports**
  - Text (`.txt`), HTML (dark mode, collapsible), PDF
  - CSV: summary, subdomains, Shodan ports/services

---

## 🛠 Installation

Clone this repo:

```bash
git clone https://github.com/akku2525/osint-tool.git
cd osint-tool
chmod +x osint-tool.sh

# install dependencies

sudo apt update
sudo apt install -y python3 python3-pip git curl jq whois nmap whatweb wkhtmltopdf chromium-browser golang
pip3 install phonenumbers holehe maigret shot-scraper shodan

## 🚀Usage
Phone number OSINT

./osint-tool.sh +919876543210

## Website OSINT

./osint-tool.sh https://example.com

## Website OSINT with Shodan

./osint-tool.sh --shodan YOUR_API_KEY https://example.com
