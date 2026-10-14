# FISH — Origin IP Discovery Tool

**Methodology:** Fingerprint → Inspect → Scan → Harvest  
**Author:** Kai Aizen / [SnailSploit](https://snailsploit.com)  
**Version:** 1.1.0

---

## What it does

FISH finds the real origin IP of a domain sitting behind a CDN or reverse proxy (Cloudflare, Akamai, Fastly, etc.) by:

1. **Fingerprinting** the canonical response — HTTP status, Server header, redirect path, body hash, page title — without following redirects, so every probe is compared on equal terms.
2. **Harvesting** candidate IP ranges from passive sources (MX records, SPF flattening, CT logs, passive DNS) or from BGP routing data (ASN → announced prefixes).
3. **Scanning** each candidate IP with a spoofed `Host:` header, scoring the raw response against the fingerprint. IPs from passive sources need only 1 matching signal; blind CIDR sweeps require 2+.
4. **Reporting** confirmed candidates with the matched signals, optionally as JSON.

No API keys required.

---

## Install

```bash
pip install httpx dnspython beautifulsoup4
```

Python 3.9+.

---

## Usage

```
fish_scan.py -t TARGET [options]

Modes (pick one):
  --auto-asn        resolve domain → IP → ASN → all announced prefixes
  --asn ASN         fetch prefixes for a known ASN number
  -c CIDR           one or more manual CIDRs (repeatable)
  -cf               target is Cloudflare-fronted — passive origin harvest
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t TARGET` | — | Target domain, no scheme |
| `-c CIDR` | — | Manual CIDR (repeatable) |
| `--asn N` | — | Resolve prefixes from ASN |
| `--auto-asn` | — | Auto-resolve ASN from current IP |
| `-cf` | — | CF-fronted target; run passive harvest |
| `-w WORDLIST` | built-in 19 | Subdomain bypass wordlist |
| `--no-subs` | false | Skip subdomain probing |
| `--concurrency N` | 150 | Max concurrent HTTP probes |
| `--timeout SEC` | 8.0 | Per-request timeout |
| `-o FILE` | — | Write JSON results to file |
| `-V` | — | Print version and exit |

---

## Examples

### Non-CF target — auto-resolve ASN

```bash
python fish_scan.py -t example.com --auto-asn
```

Resolves `example.com` → IP → ASN via BGPView, fetches all announced prefixes, sweeps them with Host-header spoofing.

### Non-CF target — known ASN

```bash
python fish_scan.py -t example.com --asn 14618
```

### Manual CIDR

```bash
python fish_scan.py -t example.com -c 203.0.113.0/24 -c 198.51.100.0/24
```

### Cloudflare-fronted target

```bash
python fish_scan.py -t example.com -cf
```

Runs passive harvest (MX → SPF → crt.sh → HackerTarget), derives `/24` candidate ranges, scans with trusted-IP threshold (1 signal) for passively-confirmed IPs and standard threshold (2 signals) for the rest.

### CF target, JSON output, no subdomain probing

```bash
python fish_scan.py -t example.com -cf -o results.json --no-subs
```

### CF target with custom subdomain wordlist

```bash
python fish_scan.py -t example.com -cf -w /path/to/subs.txt
```

---

## Output

```
[*] CF mode — passive origin harvest for example.com
[*] Loaded 15 Cloudflare IPv4 ranges

[*] MX records
    [MX]  mail.example.com → 203.0.113.42

[*] SPF flattening
[*] crt.sh CT log enumeration
    [crt.sh] 3 unique subdomains found, resolving...
    [crt.sh] staging.example.com → 203.0.113.42
[*] HackerTarget hostsearch
    [HackerTarget] www.example.com → 203.0.113.42

[*] Harvest complete — 1 candidate CIDR(s), 1 trusted IP(s):
    203.0.113.0/24

[*] Fingerprint: status=302 server='nginx/1.15.12' location='/coming-soon.html'

[*] Probing 254 IPs (1 trusted @ threshold=1) + 19 subdomains  [concurrency=150]
[+] IP   203.0.113.42        [trusted]  signals=['server:nginx/1.15.12']

[=] 1 confirmed origin candidate(s)  [3.2s]
    203.0.113.42         signals=['server:nginx/1.15.12']  status=301  [trusted]
```

### JSON output (`-o results.json`)

```json
{
  "target": "example.com",
  "fingerprint": {
    "status": 302,
    "server": "nginx/1.15.12",
    "location": "/coming-soon.html",
    "title": "",
    "body_hash": "d41d8cd98f00b204e9800998ecf8427e"
  },
  "hits": [
    {
      "ip": "203.0.113.42",
      "host": "example.com",
      "signals": ["server:nginx/1.15.12"],
      "status": 301,
      "title": "",
      "trusted": true
    }
  ],
  "elapsed_s": 3.2
}
```

---

## Scoring logic

Each candidate IP (or subdomain) is scored against the fingerprint on up to 5 signals:

| Signal | Match condition |
|--------|----------------|
| `status:N` | HTTP status code matches fingerprint |
| `title_match` | `<title>` content matches |
| `body_hash_match` | MD5 of response body matches (non-empty bodies only) |
| `server:X` | `Server` header matches |
| `location_match` | Redirect path matches (path only, scheme+host stripped) |

**Thresholds:**
- Passively-harvested IPs (MX, crt.sh, HackerTarget): **≥ 1 signal**
- Blind CIDR sweep IPs: **≥ 2 signals**

The redirect-follow bug (where `follow_redirects=True` causes every shared-host IP to score 4/4 by chasing the canonical domain) is avoided by probing without following redirects and matching the Location path as a signal instead.

---

## Known limitations

- HTTPS probing of raw IPs is skipped (cert mismatch + proxy tunnel rejection). HTTP-only for IP probes; HTTPS is tried first for named subdomains.
- BGPView has no API key requirement but may rate-limit heavy use.
- HackerTarget free tier rate-limits after ~50 queries/day.
- CIDRs broader than `/16` are skipped (65 535+ hosts — too broad to sweep blindly; narrow with `--asn` or `-c`).

---

## FISH methodology

| Phase | What happens |
|-------|-------------|
| **F**ingerprint | Fetch canonical response (no redirect follow); record status, Server, Location path, body MD5, title |
| **I**nspect | Detect CDN (CF IP ranges, CF ASNs); decide harvest vs. ASN sweep |
| **S**can | Host-header brute over candidate CIDRs + bypass subdomains; score raw responses |
| **H**arvest | Passive origin enumeration: MX, SPF ip4:, CT logs, passive DNS |
