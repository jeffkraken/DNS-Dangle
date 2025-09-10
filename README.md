DNS-Dangle
==========

DNS-Dangle is a tool that helps security researchers and defenders identify 
potentially dangling DNS records (subdomains that may be vulnerable to takeover).

It works by:
- Querying Certificate Transparency logs (via crt.sh) for subdomains
- Optionally brute-forcing hostnames from a wordlist
- Checking DNS resolution chains (CNAME → A/AAAA)
- Detecting dangling CNAMEs pointing to non-existent targets
- Probing HTTP/HTTPS for known service takeover fingerprints
- Optionally flagging NS/MX records that delegate outside the base domain
- Exporting results in CSV, JSON, or XML

--------------------------------------------------------------------
Disclaimer
--------------------------------------------------------------------
This tool is for educational use and authorized security testing only.
Scanning domains you do not own or operate may be illegal.
The authors and contributors assume no liability for misuse or damage.

--------------------------------------------------------------------
Installation
--------------------------------------------------------------------
Clone this repo and install dependencies:

    git clone https://github.com/jeffkraken/DNS-Dangle.git
    cd DNS-Dangle
    pip install -r requirements.txt

Dependencies:
- requests
- dnspython
- httpx

--------------------------------------------------------------------
Usage
--------------------------------------------------------------------
Basic CT log scan:

    python DNS-dangle.py -d example.com

Save results to CSV with custom resolvers:

    python DNS-dangle.py -d example.com --dns-server 1.1.1.1 --dns-server 8.8.8.8 -o results.csv

Skip HTTP fingerprinting (DNS-only check):

    python DNS-dangle.py -d example.com --no-http

Add subdomains from a wordlist:

    python DNS-dangle.py -d example.com --wordlist ./wordlists/short.txt

Check NS/MX records for off-domain delegation:

    python DNS-dangle.py -d example.com --ns-mx-scan

Output formats:

    python DNS-dangle.py -d example.com --format json -o results.json
    python DNS-dangle.py -d example.com --format xml -o results.xml


--------------------------------------------------------------------
Features
--------------------------------------------------------------------
 - Fetch subdomains from crt.sh

 - Optional wordlist brute-force

 - Dangling DNS detection (CNAME → NXDOMAIN)

 - HTTP/HTTPS fingerprint checks (S3, GitHub Pages, Azure, Netlify, etc.)

 - NS/MX off-domain detection

 - Output in CSV, JSON, XML

--------------------------------------------------------------------
License
--------------------------------------------------------------------
This project is licensed under the MIT License (see LICENSE).
