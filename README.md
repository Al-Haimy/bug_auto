# Bug Bounty Recon Automation
This repository contains a fully automated reconnaissance pipeline for bug bounty hunting.
It enumerates subdomains, probes live hosts, gathers historical URLs, extracts JavaScript files, searches for secrets, and runs vulnerability scans using Nuclei.



## 1. Prerequisite
- inux environment (Kali, Parrot, Ubuntu recommended)
- Python 3.10+ 
- Go (latest)
- Git

## 2. Install Required Tools
The script uses several third-party tools 
```shell
# Install Go tools
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```



## 3. Required Lists
```shell
mkdir -p /root/tools/lists
wget -O /root/tools/lists/subdomains-top1million-5000.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
wget -O /root/tools/lists/resolvers.txt https://raw.githubusercontent.com/vortexau/dnsvalidator/master/resolvers.txt
```
*Note you can adjust the paths in the bash script or just follow this and is not recommended*


## 4. Other Scripts & Tools
```bash
# SecretFinder
git clone https://github.com/m4ll0k/SecretFinder.git /root/tools/SecretFinder

# for juice script reach me for it is for sell but the script works fine without it.

# LinkFinder
git clone https://github.com/GerbenJavado/LinkFinder.git /root/tools/LinkFinder
```

## Usage
```shell
../auto.sh example.com
```

## installation 