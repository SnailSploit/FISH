#!/usr/bin/env python3
"""
FISH — Origin IP Discovery Tool  (Scan Phase)

Methodology: Fingerprint → Inspect → Scan → Harvest
Author:      Kai Aizen / SnailSploit <kai@snailsploit.com>
Version:     1.1.0

Modes
─────
  -t target.com --auto-asn            resolve domain → IP → ASN → all prefixes
  -t target.com --asn 13335           fetch prefixes for a known ASN
  -t target.com -c 1.2.3.0/24        one or more manual CIDRs
  -t target.com -cf                   target is Cloudflare-fronted — harvest
                                      origin IPs via MX, SPF, crt.sh, HackerTarget
"""

import asyncio
import argparse
import dns.resolver
import hashlib
import ipaddress
import json
import socket
import sys
import time
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

__version__ = "1.1.0"

# ── defaults ──────────────────────────────────────────────────────────────────

DEFAULT_TIMEOUT     = 8.0
DEFAULT_CONNECT     = 3.0
DEFAULT_CONCURRENCY = 150
BGPVIEW             = "https://api.bgpview.io"
CF_IPS_URL          = "https://www.cloudflare.com/ips-v4"
CF_ASNS             = {13335, 209242, 132892, 395747}

BYPASS_PREFIXES = [
    "origin", "direct", "real", "backend", "api", "dev", "staging",
    "internal", "admin", "mail", "smtp", "vpn", "cdn-origin", "source",
    "app", "www2", "secure", "portal", "server",
]


# ── data classes ──────────────────────────────────────────────────────────────

class Fingerprint:
    __slots__ = ("status", "title", "body_hash", "server", "location")

    def __init__(self, status, title, body_hash, server, location=""):
        self.status    = status
        self.title     = title
        self.body_hash = body_hash
        self.server    = server
        self.location  = location

    def __repr__(self):
        return (
            f"Fingerprint(status={self.status}, server={self.server!r}, "
            f"location={self.location!r}, title={self.title!r})"
        )


class Hit:
    __slots__ = ("ip", "host", "signals", "status", "title", "trusted")

    def __init__(self, ip, host, signals, status, title, trusted=False):
        self.ip      = ip
        self.host    = host
        self.signals = signals
        self.status  = status
        self.title   = title
        self.trusted = trusted

    def to_dict(self):
        return {
            "ip":      self.ip,
            "host":    self.host,
            "signals": self.signals,
            "status":  self.status,
            "title":   self.title,
            "trusted": self.trusted,
        }


# ── helpers ───────────────────────────────────────────────────────────────────

def extract_title(html: bytes) -> str:
    try:
        t = BeautifulSoup(html, "html.parser").title.string
        return t.strip() if t else ""
    except Exception:
        return ""


def md5(content: bytes) -> str:
    return hashlib.md5(content).hexdigest()


EMPTY_MD5 = md5(b"")


def normalize_location(raw: str) -> str:
    """Strip scheme+host from an absolute Location header → path only."""
    if raw.startswith("http"):
        p = urlparse(raw)
        return p.path + (("?" + p.query) if p.query else "")
    return raw


def ip_to_slash24(ip_str: str) -> str:
    return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))


async def fetch(client, url, host_header=None, follow=False):
    headers = {"User-Agent": "Mozilla/5.0 (compatible; FISH/1.1)", "Accept": "*/*"}
    if host_header:
        headers["Host"] = host_header
    try:
        return await client.get(url, headers=headers, follow_redirects=follow)
    except Exception:
        return None


def resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception as exc:
        _die(f"DNS resolution failed for {domain}: {exc}")


def _die(msg: str):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


# ── Cloudflare detection ──────────────────────────────────────────────────────

async def fetch_cf_networks():
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as c:
        r = await c.get(CF_IPS_URL)
        nets = []
        for line in r.text.strip().splitlines():
            try:
                nets.append(ipaddress.ip_network(line.strip()))
            except Exception:
                pass
    return nets


def is_cf_ip(ip_str: str, cf_nets) -> bool:
    addr = ipaddress.ip_address(ip_str)
    return any(addr in net for net in cf_nets)


# ── CF passive harvest ────────────────────────────────────────────────────────

def dns_query(name: str, rtype: str):
    try:
        return [r.to_text() for r in dns.resolver.resolve(name, rtype)]
    except Exception:
        return []


def flatten_spf(domain: str, cf_nets, depth=0, seen=None):
    """Recursively expand SPF include: chains; return non-CF ip4: CIDRs."""
    if depth > 5:
        return []
    if seen is None:
        seen = set()
    if domain in seen:
        return []
    seen.add(domain)

    results = []
    for txt in dns_query(domain, "TXT"):
        if "v=spf1" not in txt:
            continue
        for token in txt.split():
            if token.startswith("ip4:"):
                cidr = token[4:]
                try:
                    net   = ipaddress.ip_network(cidr, strict=False)
                    first = str(next(net.hosts(), None) or net.network_address)
                    if not is_cf_ip(first, cf_nets):
                        results.append(cidr)
                        print(f"    [SPF] ip4:{cidr}")
                except Exception:
                    pass
            elif token.startswith("include:"):
                results.extend(flatten_spf(token[8:], cf_nets, depth + 1, seen))
    return results


def resolve_mx(domain: str, cf_nets):
    ips = []
    for mx in dns_query(domain, "MX"):
        host = mx.strip().split()[-1].rstrip(".")
        try:
            ip = socket.gethostbyname(host)
            if not is_cf_ip(ip, cf_nets):
                print(f"    [MX]  {host} → {ip}")
                ips.append(ip)
        except Exception:
            pass
    return ips


async def crtsh_ips(domain: str, cf_nets):
    ips = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as c:
        try:
            r       = await c.get(url)
            entries = r.json()
        except Exception:
            print("    [crt.sh] failed or no results")
            return ips

    subs = set()
    for e in entries:
        for name in e.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name.endswith(domain):
                subs.add(name)

    print(f"    [crt.sh] {len(subs)} unique subdomains found, resolving...")
    for sub in subs:
        try:
            ip = socket.gethostbyname(sub)
            if not is_cf_ip(ip, cf_nets):
                print(f"    [crt.sh] {sub} → {ip}")
                ips.append(ip)
        except Exception:
            pass
    return ips


async def hackertarget_ips(domain: str, cf_nets):
    ips = []
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as c:
        try:
            r = await c.get(url)
            if "error" in r.text.lower() or "API count" in r.text:
                print("    [HackerTarget] rate limited or error")
                return ips
            for line in r.text.strip().splitlines():
                parts = line.split(",")
                if len(parts) != 2:
                    continue
                host, ip = parts[0].strip(), parts[1].strip()
                try:
                    ipaddress.ip_address(ip)
                    if not is_cf_ip(ip, cf_nets):
                        print(f"    [HackerTarget] {host} → {ip}")
                        ips.append(ip)
                except Exception:
                    pass
        except Exception:
            print("    [HackerTarget] request failed")
    return ips


async def harvest_cf_origin(domain: str):
    """
    Passive origin discovery for CF-fronted targets.
    Returns (cidrs: list[str], trusted_ips: set[str]).
    """
    print(f"\n[*] CF mode — passive origin harvest for {domain}")
    cf_nets = await fetch_cf_networks()
    print(f"[*] Loaded {len(cf_nets)} Cloudflare IPv4 ranges")

    raw_ips = []

    print("\n[*] MX records")
    raw_ips.extend(resolve_mx(domain, cf_nets))

    print("\n[*] SPF flattening")
    spf_cidrs = flatten_spf(domain, cf_nets)

    print("\n[*] crt.sh CT log enumeration")
    raw_ips.extend(await crtsh_ips(domain, cf_nets))

    print("\n[*] HackerTarget hostsearch")
    raw_ips.extend(await hackertarget_ips(domain, cf_nets))

    cidrs   = set(spf_cidrs)
    trusted = set(raw_ips)
    for ip in raw_ips:
        cidrs.add(ip_to_slash24(ip))

    cidrs = sorted(cidrs)
    print(f"\n[*] Harvest complete — {len(cidrs)} candidate CIDR(s), {len(trusted)} trusted IP(s):")
    for c in cidrs:
        print(f"    {c}")
    return cidrs, trusted


# ── ASN resolution ────────────────────────────────────────────────────────────

async def asn_from_ip(ip: str) -> int:
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as c:
        r = await c.get(f"{BGPVIEW}/ip/{ip}")
        r.raise_for_status()
        prefixes = r.json().get("data", {}).get("prefixes", [])
        if not prefixes:
            _die(f"BGPView returned no ASN data for {ip}")
        asn  = prefixes[0]["asn"]["asn"]
        name = prefixes[0]["asn"].get("name", "")
        print(f"[*] {ip} → ASN{asn} ({name})")
        return asn


async def cidrs_from_asn(asn: int):
    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as c:
        r = await c.get(f"{BGPVIEW}/asn/{asn}/prefixes")
        r.raise_for_status()
        ipv4 = [p["prefix"] for p in r.json().get("data", {}).get("ipv4_prefixes", [])]
        print(f"[*] ASN{asn} — {len(ipv4)} IPv4 prefix(es)")
        for p in ipv4:
            print(f"    {p}")
        return ipv4


async def auto_resolve_cidrs(domain: str):
    ip  = resolve_ip(domain)
    print(f"[*] {domain} → {ip}")
    asn = await asn_from_ip(ip)
    if asn in CF_ASNS:
        _die(f"ASN{asn} is Cloudflare — use -cf for CF-fronted targets")
    return await cidrs_from_asn(asn)


# ── fingerprinting ────────────────────────────────────────────────────────────

async def fingerprint_target(domain: str, timeout: httpx.Timeout) -> Fingerprint:
    """
    Fetch the canonical response WITHOUT following redirects.
    Probes compare against this raw first response, so redirect-path matching
    works without chasing back to the origin domain via DNS.
    """
    async with httpx.AsyncClient(timeout=timeout, verify=False) as c:
        r = await fetch(c, f"https://{domain}", follow=False)
        if r is None:
            r = await fetch(c, f"http://{domain}", follow=False)
        if r is None:
            _die(f"Could not reach {domain} (both HTTPS and HTTP failed)")

        loc = normalize_location(r.headers.get("location", ""))
        fp  = Fingerprint(
            status    = r.status_code,
            title     = extract_title(r.content),
            body_hash = md5(r.content),
            server    = r.headers.get("server", ""),
            location  = loc,
        )
        parts = [f"status={fp.status}", f"server={fp.server!r}", f"location={fp.location!r}"]
        if fp.title:
            parts.append(f"title={fp.title!r}")
        print(f"[*] Fingerprint: {' '.join(parts)}")
        return fp


# ── scoring ───────────────────────────────────────────────────────────────────

def score(fp: Fingerprint, status: int, title: str, bhash: str,
          server: str, location: str = "") -> list:
    signals = []
    if status == fp.status:
        signals.append(f"status:{status}")
    if title and fp.title and title == fp.title:
        signals.append("title_match")
    if bhash == fp.body_hash and bhash != EMPTY_MD5:
        signals.append("body_hash_match")
    if fp.server and server and server == fp.server:
        signals.append(f"server:{server}")
    if location and fp.location and location == fp.location:
        signals.append("location_match")
    return signals


# ── probing ───────────────────────────────────────────────────────────────────

async def probe_ip(sem, client, ip_str: str, domain: str,
                   fp: Fingerprint, hits: list, min_signals: int = 2):
    """
    HTTP only — raw-IP HTTPS fails cert validation and stalls the proxy.
    No redirect follow — avoids matching every shared-host IP that redirects
    to the canonical URL and would score 4/4 after following.
    """
    async with sem:
        r = await fetch(client, f"http://{ip_str}", host_header=domain, follow=False)
        if r is None:
            return
        loc     = normalize_location(r.headers.get("location", ""))
        signals = score(fp, r.status_code, extract_title(r.content),
                        md5(r.content), r.headers.get("server", ""), location=loc)
        if len(signals) >= min_signals:
            trusted = min_signals == 1
            hits.append(Hit(ip_str, domain, signals, r.status_code,
                            extract_title(r.content), trusted=trusted))
            tag = " [trusted]" if trusted else ""
            print(f"[+] IP   {ip_str}{tag}  signals={signals}")


async def probe_subdomain(sem, client, sub: str, domain: str,
                          fp: Fingerprint, hits: list):
    """
    Subdomain probing — HTTPS first (valid cert via SNI), HTTP fallback.
    No redirect follow.
    """
    host = f"{sub}.{domain}"
    async with sem:
        for scheme in ("https", "http"):
            r = await fetch(client, f"{scheme}://{host}", follow=False)
            if r is None:
                continue
            loc     = normalize_location(r.headers.get("location", ""))
            signals = score(fp, r.status_code, extract_title(r.content),
                            md5(r.content), r.headers.get("server", ""), location=loc)
            if len(signals) >= 2:
                hits.append(Hit(host, host, signals, r.status_code,
                                extract_title(r.content)))
                print(f"[+] SUB  {host} ({scheme})  signals={signals}")
            break


# ── scan orchestration ────────────────────────────────────────────────────────

async def run_scan(domain: str, cidrs, subdomains, fp: Fingerprint,
                   trusted_ips=None, concurrency: int = DEFAULT_CONCURRENCY,
                   timeout: httpx.Timeout = None):
    """
    trusted_ips — IPs from passive harvest (lower confidence threshold: 1 signal).
    Blind CIDR sweep IPs require 2+ signals to reduce false positives.
    """
    if timeout is None:
        timeout = httpx.Timeout(DEFAULT_TIMEOUT, connect=DEFAULT_CONNECT)
    trusted = trusted_ips or set()
    hits    = []
    sem     = asyncio.Semaphore(concurrency)

    ips = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen < 16:
                print(f"[!] Skipping {cidr} (/{net.prefixlen} too broad — narrow manually)")
                continue
            ips.extend(str(ip) for ip in net.hosts())
        except ValueError as exc:
            print(f"[!] Bad CIDR {cidr}: {exc}")

    print(f"\n[*] Probing {len(ips)} IPs"
          + (f" ({len(trusted)} trusted @ threshold=1)" if trusted else "")
          + f" + {len(subdomains)} subdomains  [concurrency={concurrency}]")

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        tasks = (
            [probe_ip(sem, client, ip, domain, fp, hits,
                      min_signals=1 if ip in trusted else 2) for ip in ips]
            + [probe_subdomain(sem, client, s, domain, fp, hits) for s in subdomains]
        )
        await asyncio.gather(*tasks)

    return hits


# ── main ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fish_scan",
        description="FISH — Origin IP discovery behind CDN/reverse-proxy (Scan Phase)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  fish_scan.py -t example.com --auto-asn
  fish_scan.py -t example.com --asn 13335
  fish_scan.py -t example.com -c 203.0.113.0/24 -c 198.51.100.0/24
  fish_scan.py -t example.com -cf
  fish_scan.py -t example.com -cf -o results.json --no-subs
        """,
    )
    p.add_argument("-t", "--target",      required=True,
                   help="Target domain (no scheme, no trailing slash)")
    p.add_argument("-c", "--cidr",        action="append", default=[],
                   help="Manual CIDR to scan (repeatable)")
    p.add_argument("--asn",              type=int,
                   help="Resolve prefixes from a known ASN number")
    p.add_argument("--auto-asn",         action="store_true",
                   help="Auto-resolve ASN from the target's current IP")
    p.add_argument("-cf",                action="store_true",
                   help="CF-fronted target — harvest origin via MX/SPF/crt.sh/HackerTarget")
    p.add_argument("-w", "--wordlist",
                   help="Subdomain bypass wordlist (one per line); overrides built-in list")
    p.add_argument("--no-subs",          action="store_true",
                   help="Skip subdomain probing entirely")
    p.add_argument("--concurrency",      type=int, default=DEFAULT_CONCURRENCY, metavar="N",
                   help=f"Max concurrent HTTP probes (default: {DEFAULT_CONCURRENCY})")
    p.add_argument("--timeout",          type=float, default=DEFAULT_TIMEOUT, metavar="SEC",
                   help=f"Per-request timeout in seconds (default: {DEFAULT_TIMEOUT})")
    p.add_argument("-o", "--output",
                   help="Write JSON results to this file")
    p.add_argument("-V", "--version",    action="version", version=f"%(prog)s {__version__}")
    return p


def main():
    args   = build_parser().parse_args()
    t_http = httpx.Timeout(args.timeout, connect=min(args.timeout, DEFAULT_CONNECT))

    # ── mode validation ───────────────────────────────────────────────────────
    modes = sum([bool(args.cidr), bool(args.asn), args.auto_asn, args.cf])
    if modes > 1:
        _die("Use only one of: -c, --asn, --auto-asn, -cf")

    # ── subdomain list ────────────────────────────────────────────────────────
    if args.no_subs:
        subdomains = []
    elif args.wordlist:
        with open(args.wordlist) as fh:
            subdomains = [l.strip() for l in fh if l.strip()]
    else:
        subdomains = BYPASS_PREFIXES

    # ── CIDR / trusted-IP resolution ─────────────────────────────────────────
    cidrs       = list(args.cidr)
    trusted_ips = set()

    if args.cf:
        cidrs, trusted_ips = asyncio.run(harvest_cf_origin(args.target))
        if not cidrs:
            _die("Harvest returned no candidates — check DNS or try a larger wordlist")
    elif args.auto_asn:
        cidrs = asyncio.run(auto_resolve_cidrs(args.target))
    elif args.asn:
        cidrs = asyncio.run(cidrs_from_asn(args.asn))

    if not cidrs and not subdomains:
        _die("Nothing to scan — provide -cf, --auto-asn, --asn, or -c CIDR")

    # ── fingerprint + scan ────────────────────────────────────────────────────
    fp   = asyncio.run(fingerprint_target(args.target, t_http))
    t0   = time.monotonic()
    hits = asyncio.run(
        run_scan(args.target, cidrs, subdomains, fp,
                 trusted_ips=trusted_ips,
                 concurrency=args.concurrency,
                 timeout=t_http)
    )
    elapsed = time.monotonic() - t0

    # ── results ───────────────────────────────────────────────────────────────
    print(f"\n[=] {len(hits)} confirmed origin candidate(s)  [{elapsed:.1f}s]")
    for h in hits:
        tag = " [trusted]" if h.trusted else ""
        print(f"    {h.ip:<20} signals={h.signals}  status={h.status}{tag}")
        if h.title:
            print(f"    {'':20} title={h.title!r}")

    if args.output:
        out = {
            "target":      args.target,
            "fingerprint": {
                "status":    fp.status,
                "server":    fp.server,
                "location":  fp.location,
                "title":     fp.title,
                "body_hash": fp.body_hash,
            },
            "hits": [h.to_dict() for h in hits],
            "elapsed_s": round(elapsed, 2),
        }
        with open(args.output, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"[*] Results written to {args.output}")


if __name__ == "__main__":
    main()
