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

    git clone https://github.com/<yourname>/DNS-Dangle.git
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

    python ct_dangling_dns_scan.py -d example.com

Save results to CSV with custom resolvers:

    python ct_dangling_dns_scan.py -d example.com --dns-server 1.1.1.1 --dns-server 8.8.8.8 -o results.csv

Skip HTTP fingerprinting (DNS-only check):

    python ct_dangling_dns_scan.py -d example.com --no-http

Add subdomains from a wordlist:

    python ct_dangling_dns_scan.py -d example.com --wordlist ./subdomains.txt

Check NS/MX records for off-domain delegation:

    python ct_dangling_dns_scan.py -d example.com --ns-mx-scan

Output formats:

    python ct_dangling_dns_scan.py -d example.com --format json -o results.json
    python ct_dangling_dns_scan.py -d example.com --format xml -o results.xml

--------------------------------------------------------------------
Example Output (CSV)
--------------------------------------------------------------------
host              | has_cname | cname_chain                | a_records | potential_dangling | dangling_reason                         | service_or_hint | ns_off_domain | mx_off_domain
------------------+-----------+----------------------------+-----------+--------------------+------------------------------------------+-----------------+---------------+---------------
blog.example.com  | True      | blog.example.com -> s3…   |           | True               | CNAME target does not resolve (no A/AAAA) | AWS S3          | False         | False
mail.example.com  | False     | -                          | 93.184.1.1| False              |                                          |                 | True          | True

--------------------------------------------------------------------
Features
--------------------------------------------------------------------
[x] Fetch subdomains from crt.sh
[x] Optional wordlist brute-force
[x] Dangling DNS detection (CNAME → NXDOMAIN)
[x] HTTP/HTTPS fingerprint checks (S3, GitHub Pages, Azure, Netlify, etc.)
[x] NS/MX off-domain detection
[x] Output in CSV, JSON, XML

--------------------------------------------------------------------
License
--------------------------------------------------------------------
This project is licensed under the MIT License (see LICENSE).
