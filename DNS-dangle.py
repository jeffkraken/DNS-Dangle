#!/usr/bin/env python3
"""
The DNS Dangle!
- Queries crt.sh for subdomains of a given domain (via JSON endpoint)
- (NEW) Optionally brute-forces hostnames from a wordlist
- Resolves DNS (CNAME/A/AAAA) and checks for dangling DNS conditions
- (NEW) Checks NS/MX records for "off-domain" targets (outsourced/delegated)
- (NEW) Outputs CSV/JSON/XML

Usage:
  python ct_dangling_dns_scan.py -d example.com -o results.csv --format csv --ns-mx-scan --wordlist words.txt

Dependencies:
  pip install requests dnspython httpx
"""

from __future__ import annotations
import argparse
import concurrent.futures
import csv
import ipaddress
import json
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple

import requests
import dns.resolver
import dns.exception
import dns.name
import dns.rdatatype
import httpx
import xml.etree.ElementTree as ET

CRT_URL = "https://crt.sh/"
USER_AGENT = "DNS-Dangle/1.1 (educational; info@cybergoblin.org)"

FINGERPRINTS: Dict[str, Dict[str, List[str]]] = {
    "AWS S3": {
        "domains": ["s3.amazonaws.com", ".s3-website", ".amazonaws.com"],
        "body": ["NoSuchBucket", "The specified bucket does not exist"],
        "status": ["404", "400"],
    },
    "GitHub Pages": {
        "domains": [".github.io"],
        "body": ["There isn't a GitHub Pages site here."],
        "status": ["404"],
    },
    "Heroku": {
        "domains": [".herokuapp.com"],
        "body": ["No such app"],
        "status": ["404"],
    },
    "Azure": {
        "domains": [
            ".azurewebsites.net",
            ".cloudapp.net",
            ".trafficmanager.net",
            ".blob.core.windows.net",
        ],
        "body": ["The resource you are looking for has been removed"],
        "status": ["404"],
    },
    "Netlify": {
        "domains": [".netlify.app"],
        "body": ["Not Found", "No such site", "Site Not Found"],
        "status": ["404"],
    },
    "Cloudflare Pages": {
        "domains": [".pages.dev"],
        "body": ["Failed to find a registered site"],
        "status": ["404"],
    },
    "Read the Docs": {
        "domains": [".readthedocs.io"],
        "body": ["Either this page does not exist or you do not have the permissions"],
        "status": ["404"],
    },
    "Unbounce": {
        "domains": [".unbouncepages.com"],
        "body": ["The requested URL was not found on this server"],
        "status": ["404"],
    },
    "Shopify": {
        "domains": [".myshopify.com"],
        "body": ["Sorry, this shop is currently unavailable"],
        "status": ["404"],
    },
    "Squarespace": {
        "domains": [".squarespace.com"],
        "body": ["No Such Page"],
        "status": ["404"],
    },
    "Fastly": {
        "domains": [".fastly.net"],
        "body": ["Fastly error: unknown domain"],
        "status": ["404"],
    },
    "WP Engine": {
        "domains": [".wpengine.com"],
        "body": ["The site you were looking for couldn't be found"],
        "status": ["404"],
    },
}

@dataclass
class DnsCheckResult:
    host: str
    has_cname: bool = False
    cname_chain: List[str] = field(default_factory=list)
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    error: Optional[str] = None
    potential_dangling: bool = False
    dangling_reason: Optional[str] = None
    http_fingerprint_service: Optional[str] = None
    http_evidence: Optional[str] = None
    ns_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_off_domain: bool = False
    mx_off_domain: bool = False

def fetch_ct_subdomains(domain: str) -> Set[str]:
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(CRT_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[!] Failed to query crt.sh: {e}", file=sys.stderr)
        return set()

    subs: Set[str] = set()
    for entry in data:
        name_val = (entry.get("name_value") or "")
        for raw in name_val.splitlines():
            host = raw.strip().lower().rstrip(".")
            if host.endswith("." + domain) or host == domain:
                subs.add(host)
    return subs

def read_wordlist(path: str, domain: str) -> Set[str]:
    extra: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip().lower()
                if not w or w.startswith("#"):
                    continue
                # Only simple, safe labels
                if all(c.isalnum() or c in "-*" for c in w):
                    if "*" in w:
                        # allow star patterns like "*.dev" -> dev.example.com and *.dev.example.com (skip star literal)
                        label = w.replace("*", "").strip(".-")
                        if label:
                            extra.add(f"{label}.{domain}")
                    else:
                        extra.add(f"{w}.{domain}")
    except Exception as e:
        print(f"[!] Could not read wordlist '{path}': {e}", file=sys.stderr)
    return extra

def resolve_dns(host: str, resolver: dns.resolver.Resolver, max_chain: int = 10) -> DnsCheckResult:
    result = DnsCheckResult(host=host)
    try:
        seen: Set[str] = set()
        current = dns.name.from_text(host)
        hops = 0

        while hops < max_chain:
            hops += 1
            try:
                ans = resolver.resolve(current, dns.rdatatype.CNAME, raise_on_no_answer=False)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                ans = None
            except dns.exception.DNSException as e:
                result.error = f"CNAME resolve error: {e.__class__.__name__}"
                return result

            if ans and len(ans) > 0:
                result.has_cname = True
                target = ans[0].target.to_text().rstrip(".")
                result.cname_chain.append(target)
                if target in seen:
                    result.error = "CNAME loop detected"
                    return result
                seen.add(target)
                current = dns.name.from_text(target)
                continue
            else:
                a_records = []
                aaaa_records = []
                try:
                    a_ans = resolver.resolve(current, dns.rdatatype.A, raise_on_no_answer=False)
                    if a_ans:
                        a_records = [r.address for r in a_ans]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    pass
                except dns.exception.DNSException as e:
                    result.error = f"A resolve error: {e.__class__.__name__}"
                    return result

                try:
                    aaaa_ans = resolver.resolve(current, dns.rdatatype.AAAA, raise_on_no_answer=False)
                    if aaaa_ans:
                        aaaa_records = [r.address for r in aaaa_ans]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    pass
                except dns.exception.DNSException as e:
                    result.error = f"AAAA resolve error: {e.__class__.__name__}"
                    return result

                result.a_records = a_records
                result.aaaa_records = aaaa_records
                if result.has_cname and not (a_records or aaaa_records):
                    result.potential_dangling = True
                    result.dangling_reason = "CNAME target does not resolve (no A/AAAA)"
                return result

        result.error = "Max CNAME chain exceeded"
        return result
    except dns.exception.DNSException as e:
        result.error = f"DNS error: {e.__class__.__name__}"
        return result

def service_hint_from_cname_chain(cname_chain: List[str]) -> Optional[str]:
    joined = " ".join(cname_chain).lower()
    for service, fp in FINGERPRINTS.items():
        for dom in fp.get("domains", []):
            if dom in joined:
                return service
    return None

async def probe_http_for_fingerprints(host: str, timeout: float = 10.0) -> Tuple[Optional[str], Optional[str]]:
    urls = [f"http://{host}", f"https://{host}"]
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
        for url in urls:
            try:
                r = await client.get(url)
                status = str(r.status_code)
                text = (r.text or "")[:4000]
                for service, fp in FINGERPRINTS.items():
                    statuses = fp.get("status", [])
                    bodies = fp.get("body", [])
                    status_ok = (not statuses) or (status in statuses)
                    body_ok = any(s.lower() in text.lower() for s in bodies) if bodies else False
                    if status_ok and body_ok:
                        return service, f"{url} -> {status} matched body snippet"
            except Exception:
                continue
    return None, None

def check_ns_mx(host: str, domain: str, resolver: dns.resolver.Resolver) -> Tuple[List[str], bool, List[str], bool]:
    """
    Returns (ns_records, ns_off_domain, mx_records, mx_off_domain).
    - ns_off_domain: True if any NS target does NOT end with the base domain (delegation/off-domain).
    - mx_off_domain: True if any MX target does NOT end with the base domain.
    """
    ns_records: List[str] = []
    mx_records: List[str] = []
    ns_off = False
    mx_off = False

    try:
        ns_ans = resolver.resolve(host, dns.rdatatype.NS, raise_on_no_answer=False)
        if ns_ans:
            ns_records = [r.target.to_text().rstrip(".").lower() for r in ns_ans]
            ns_off = any(not n.endswith("." + domain) and n != domain for n in ns_records)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
        pass

    try:
        mx_ans = resolver.resolve(host, dns.rdatatype.MX, raise_on_no_answer=False)
        if mx_ans:
            mx_records = [r.exchange.to_text().rstrip(".").lower() for r in mx_ans]
            mx_off = any(not m.endswith("." + domain) and m != domain for m in mx_records)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException):
        pass

    return ns_records, ns_off, mx_records, mx_off

def chunked(iterable, size):
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

def write_output(results: List[DnsCheckResult], path: str, fmt: str):
    fmt = fmt.lower()
    if fmt == "csv":
        fieldnames = [
            "host", "has_cname", "cname_chain", "a_records", "aaaa_records",
            "potential_dangling", "dangling_reason", "service_or_hint", "http_evidence",
            "ns_records", "ns_off_domain", "mx_records", "mx_off_domain", "error",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for r in sorted(results, key=lambda x: x.host):
                w.writerow({
                    "host": r.host,
                    "has_cname": r.has_cname,
                    "cname_chain": " -> ".join(r.cname_chain),
                    "a_records": ";".join(r.a_records),
                    "aaaa_records": ";".join(r.aaaa_records),
                    "potential_dangling": r.potential_dangling,
                    "dangling_reason": r.dangling_reason or "",
                    "service_or_hint": r.http_fingerprint_service or "",
                    "http_evidence": (r.http_evidence or "")[:200],
                    "ns_records": ";".join(r.ns_records),
                    "ns_off_domain": r.ns_off_domain,
                    "mx_records": ";".join(r.mx_records),
                    "mx_off_domain": r.mx_off_domain,
                    "error": r.error or "",
                })
    elif fmt == "json":
        payload = []
        for r in results:
            payload.append({
                "host": r.host,
                "has_cname": r.has_cname,
                "cname_chain": r.cname_chain,
                "a_records": r.a_records,
                "aaaa_records": r.aaaa_records,
                "potential_dangling": r.potential_dangling,
                "dangling_reason": r.dangling_reason,
                "service_or_hint": r.http_fingerprint_service,
                "http_evidence": r.http_evidence,
                "ns_records": r.ns_records,
                "ns_off_domain": r.ns_off_domain,
                "mx_records": r.mx_records,
                "mx_off_domain": r.mx_off_domain,
                "error": r.error,
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    elif fmt == "xml":
        # XML-friendly output with predictable tags/encodings
        root = ET.Element("scanResults")
        for r in sorted(results, key=lambda x: x.host):
            item = ET.SubElement(root, "host")
            ET.SubElement(item, "name").text = r.host
            ET.SubElement(item, "hasCNAME").text = str(r.has_cname).lower()
            ET.SubElement(item, "cnameChain").text = " -> ".join(r.cname_chain)
            ET.SubElement(item, "aRecords").text = ";".join(r.a_records)
            ET.SubElement(item, "aaaaRecords").text = ";".join(r.aaaa_records)
            ET.SubElement(item, "potentialDangling").text = str(r.potential_dangling).lower()
            ET.SubElement(item, "danglingReason").text = (r.dangling_reason or "")
            ET.SubElement(item, "serviceOrHint").text = (r.http_fingerprint_service or "")
            ET.SubElement(item, "httpEvidence").text = (r.http_evidence or "")
            ET.SubElement(item, "nsRecords").text = ";".join(r.ns_records)
            ET.SubElement(item, "nsOffDomain").text = str(r.ns_off_domain).lower()
            ET.SubElement(item, "mxRecords").text = ";".join(r.mx_records)
            ET.SubElement(item, "mxOffDomain").text = str(r.mx_off_domain).lower()
            ET.SubElement(item, "error").text = (r.error or "")
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")  # Python 3.9+
        tree.write(path, encoding="utf-8", xml_declaration=True)
    else:
        raise ValueError(f"Unsupported format: {fmt}")

def main():
    parser = argparse.ArgumentParser(description="Scan CT logs for subdomains and check for dangling DNS.")
    parser.add_argument("-d", "--domain", required=True, help="Base domain to search (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Write results to this file")
    parser.add_argument("--format", choices=["csv", "json", "xml"], default="csv", help="Output format (default: csv)")
    parser.add_argument("--dns-server", action="append", help="Custom DNS resolver IP (can be used multiple times)")
    parser.add_argument("--concurrency", type=int, default=20, help="Parallel DNS/HTTP checks (default: 20)")
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP fingerprint probing")
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS timeout seconds (default: 5)")
    parser.add_argument("--wordlist", help="Path to wordlist file for host brute-force (adds <word>.<domain>)")
    parser.add_argument("--ns-mx-scan", action="store_true", help="Check NS/MX for base domain and delegated subzones")
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    print(f"[*] Querying crt.sh for subdomains of {domain} ...")
    subs = fetch_ct_subdomains(domain)

    # Wordlist brute-force (simple prefix.<domain>)
    if args.wordlist:
        print(f"[*] Adding hosts from wordlist: {args.wordlist}")
        subs |= read_wordlist(args.wordlist, domain)

    if not subs:
        print("[!] No hostnames found (CT + wordlist empty).")
        sys.exit(1)
    print(f"[+] Total unique hostnames to test: {len(subs)}")

    # DNS resolver
    resolver = dns.resolver.Resolver()
    if args.dns_server:
        resolver.nameservers = args.dns_server
        print(f"[*] Using custom DNS servers: {', '.join(args.dns_server)}")
    resolver.lifetime = args.timeout
    resolver.timeout = args.timeout

    # Resolve A/AAAA/CNAME
    print("[*] Resolving DNS and checking for dangling conditions...")
    results: List[DnsCheckResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {pool.submit(resolve_dns, h, resolver): h for h in subs}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r.cname_chain:
                hint = service_hint_from_cname_chain(r.cname_chain)
                if hint and not r.http_fingerprint_service:
                    r.http_fingerprint_service = hint + " (CNAME hint)"
            results.append(r)

    # Optional HTTP fingerprints
    if not args.no_http:
        print("[*] Probing HTTP/HTTPS for takeover fingerprints...")
        try:
            import asyncio
            async def run_http_checks(items: List[DnsCheckResult]):
                sem = asyncio.Semaphore(args.concurrency)
                async def worker(item: DnsCheckResult):
                    async with sem:
                        svc, evidence = await probe_http_for_fingerprints(item.host)
                        if svc:
                            item.potential_dangling = True
                            item.http_fingerprint_service = svc
                            item.http_evidence = evidence
                await asyncio.gather(*(worker(r) for r in items))
            asyncio.run(run_http_checks(results))
        except Exception as e:
            print(f"[!] HTTP probing encountered an error (continuing without it): {e}")

    # Optional NS/MX checks
    if args.ns_mx_scan:
        print("[*] Checking NS/MX for off-domain targets...")
        for r in results:
            ns_records, ns_off, mx_records, mx_off = check_ns_mx(r.host, domain, resolver)
            r.ns_records = ns_records
            r.ns_off_domain = ns_off
            r.mx_records = mx_records
            r.mx_off_domain = mx_off

    # Summary to stdout
    print("\n=== Potentially Dangling (heuristics) ===")
    flagged = [r for r in results if r.potential_dangling or r.http_fingerprint_service]
    if not flagged:
        print("No obvious dangling DNS found.")
    else:
        for r in sorted(flagged, key=lambda x: x.host):
            reason_bits = []
            if r.dangling_reason:
                reason_bits.append(r.dangling_reason)
            if r.http_fingerprint_service:
                reason_bits.append(f"Service/fingerprint: {r.http_fingerprint_service}")
            if r.http_evidence:
                reason_bits.append(f"Evidence: {r.http_evidence}")
            reason = " | ".join(reason_bits) if reason_bits else "Suspicious"
            cname = " -> ".join(r.cname_chain) if r.cname_chain else "-"
            print(f"- {r.host} | CNAME: {cname} | {reason}")

    # Write file if requested
    if args.output:
        write_output(results, args.output, args.format)
        print(f"\n[+] Results written to {args.output} ({args.format.upper()})")

    print("\nDone.")

if __name__ == "__main__":
    main()
