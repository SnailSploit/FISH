#!/usr/bin/env python3
"""FISH 2 — origin IP discovery behind a CDN or reverse proxy.

Fingerprint → Inspect → Harvest → Confirm.

Same job as FISH 1.1, stricter evidence:
  status 1, server 2, redirect path 3, title 4, body 5, certificate name 6.
  A confirm needs weight >= 5. Edge headers veto the match.
  A passive address is not expanded into a /24.
  TLS to the raw address uses the real hostname as SNI.

Stdlib only. Python 3.9+.

Author: Kai Aizen / SnailSploit
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed

__version__ = "2.0.0"

UA = "FISH/2.0 (authorized origin desk)"
EMPTY_MD5 = hashlib.md5(b"").hexdigest()
DOH = "https://cloudflare-dns.com/dns-query"
CF_IPS = "https://www.cloudflare.com/ips-v4"
RIPE_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"

EDGE_ASNS = {13335, 209242, 132892, 395747, 54113, 20940, 16625, 21342, 19551}
CF_ASNS = {13335, 209242, 132892, 395747}
ASN_NAME = {
    13335: "Cloudflare",
    209242: "Cloudflare",
    132892: "Cloudflare",
    395747: "Cloudflare",
    54113: "Fastly",
    20940: "Akamai",
    16625: "Akamai",
    21342: "Akamai",
    19551: "Imperva",
}
BYPASS = [
    "origin", "direct", "real", "backend", "api", "dev", "staging",
    "internal", "admin", "mail", "smtp", "vpn", "cdn-origin", "source",
    "app", "www2", "secure", "portal", "server",
]
EDGE_SERVER = re.compile(r"cloudflare|akamai|fastly|sucuri|vercel|cloudfront|imperva|incapsula", re.I)
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def die(msg: str) -> None:
    eprint(f"[!] {msg}")
    raise SystemExit(1)


def normalize_domain(raw: str) -> str:
    s = raw.strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    s = re.sub(r":\d+$", "", s).rstrip(".")
    if not HOST_RE.match(s):
        die("target must be a public hostname, with no scheme")
    if s.endswith((".local", ".internal", ".localhost", ".localdomain")) or s == "localhost":
        die("internal names are refused")
    return s


def ipv4_ok(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_public(ip: str) -> bool:
    if not ipv4_ok(ip):
        return False
    addr = ipaddress.IPv4Address(ip)
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or addr in ipaddress.ip_network("100.64.0.0/10")
        or addr in ipaddress.ip_network("192.0.2.0/24")
        or addr in ipaddress.ip_network("198.51.100.0/24")
        or addr in ipaddress.ip_network("203.0.113.0/24")
    )


def slash24(ip: str) -> str:
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(net)


def host_count(net: ipaddress.IPv4Network) -> int:
    if net.prefixlen >= 31:
        return net.num_addresses
    return max(0, net.num_addresses - 2)


def normalize_location(raw: str) -> str:
    raw = (raw or "").strip()
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            u = urllib.parse.urlsplit(raw)
            return u.path + (("?" + u.query) if u.query else "")
        except ValueError:
            return raw
    return raw.split("#", 1)[0]


def dns_name_matches(pattern: str, domain: str) -> bool:
    name = pattern.lower().rstrip(".")
    host = domain.lower().rstrip(".")
    if name == host:
        return True
    if not name.startswith("*."):
        return False
    rest = name[2:]
    if not host.endswith("." + rest):
        return False
    left = host[: -(len(rest) + 1)]
    return bool(left) and "." not in left


def extract_title(body: bytes) -> str:
    m = re.search(br"<title[^>]*>([^<]{0,180})", body[:12000], re.I)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()


def md5(body: bytes) -> str:
    return hashlib.md5(body).hexdigest()


def http_json(url: str, timeout: float, accept: str = "application/json"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.loads(res.read().decode("utf-8", "replace"))


def http_text(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.read(1_500_000).decode("utf-8", "replace")


def doh(name: str, rtype: str, timeout: float = 5.0) -> list[str]:
    q = urllib.parse.urlencode({"name": name, "type": rtype})
    try:
        data = http_json(f"{DOH}?{q}", timeout, accept="application/dns-json")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    if data.get("Status") != 0:
        return []
    out = []
    for ans in data.get("Answer") or []:
        raw = str(ans.get("data") or "")
        raw = raw.replace('" "', "").strip().strip('"')
        if raw:
            out.append(raw)
    return out


def unchunk(body: bytes) -> bytes | None:
    parts = []
    off = 0
    while off < len(body):
        end = body.find(b"\r\n", off)
        if end < 0:
            return None
        line = body[off:end].split(b";", 1)[0]
        try:
            size = int(line, 16)
        except ValueError:
            return None
        off = end + 2
        if size == 0:
            return b"".join(parts)
        if off + size > len(body):
            return None
        parts.append(body[off : off + size])
        off += size + 2
    return None


def decode_body(headers: dict[str, str], body: bytes) -> bytes:
    if "chunked" in headers.get("transfer-encoding", ""):
        body = unchunk(body) or body
    enc = headers.get("content-encoding", "").lower()
    try:
        if "gzip" in enc:
            return zlib.decompress(body, 16 + zlib.MAX_WBITS)
        if "deflate" in enc:
            return zlib.decompress(body)
    except zlib.error:
        return body
    return body


def parse_http(buf: bytes) -> dict | None:
    sep = buf.find(b"\r\n\r\n")
    if sep < 0:
        return None
    head = buf[:sep].decode("latin1", "replace")
    lines = head.split("\r\n")
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
    if not m:
        return None
    headers: dict[str, str] = {}
    cookies: list[str] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()
        if key == "set-cookie":
            cookies.append(val)
        elif key not in headers:
            headers[key] = val
    body = decode_body(headers, buf[sep + 4 : sep + 4 + 65536])
    return {"status": int(m.group(1)), "headers": headers, "cookies": cookies, "body": body}


def cdn_providers(headers: dict[str, str], cookies: list[str]) -> list[str]:
    blob = "\n".join(f"{k}:{v}" for k, v in headers.items())
    server = headers.get("server", "")
    cookie = ";".join(cookies)
    found = []

    def add(name: str, hit: bool) -> None:
        if hit:
            found.append(name)

    add("Cloudflare", bool(re.search(r"cf-ray|cf-cache-status", blob, re.I) or re.search(r"cloudflare", server, re.I)))
    add("Akamai", bool(re.search(r"x-akamai|akamaighost", blob, re.I)))
    add("Fastly", bool(re.search(r"x-fastly|fastly-debug|x-timer", blob, re.I)))
    add("CloudFront", "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers)
    add("Imperva", bool(re.search(r"imperva|incapsula", blob, re.I) or re.search(r"incap_ses|visid_incap", cookie, re.I)))
    add("Sucuri", "x-sucuri-id" in headers or bool(re.search(r"sucuri", server, re.I)))
    add("Vercel", "x-vercel-id" in headers or bool(re.search(r"vercel", server, re.I)))
    add("Netlify", "x-nf-request-id" in headers)
    return found


def read_cert(der: bytes | None, domain: str) -> dict | None:
    if not der:
        return None
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer", "-ext", "subjectAltName"],
            input=der,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = proc.stdout.decode("utf-8", "replace")
    if not text.strip():
        return None
    subject = ""
    issuer = ""
    names: list[str] = []
    for line in text.splitlines():
        if line.lower().startswith("subject="):
            m = re.search(r"CN\s*=\s*([^,/]+)", line)
            subject = m.group(1).strip() if m else ""
        elif line.lower().startswith("issuer="):
            m = re.search(r"(?:O|CN)\s*=\s*([^,/]+)", line)
            issuer = m.group(1).strip() if m else line.split("=", 1)[-1].strip()
        else:
            for part in line.split(","):
                m = re.search(r"DNS:([^\s,]+)", part)
                if m:
                    names.append(m.group(1))
    if subject and subject not in names:
        names.insert(0, subject)
    return {
        "subject": subject,
        "issuer": issuer,
        "names": names[:8],
        "matches": any(dns_name_matches(n, domain) for n in names),
        "edge": bool(re.search(r"cloudflare|akamai|fastly", issuer, re.I)),
    }


def _exchange(ip: str, port: int, domain: str, path: str, timeout: float, use_tls: bool) -> dict | None:
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout)
        sock.settimeout(timeout)
        cert = None
        active = sock
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["http/1.1"])
            active = ctx.wrap_socket(sock, server_hostname=domain)
            cert = read_cert(active.getpeercert(binary_form=True), domain)
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {UA}\r\n"
            f"Accept: */*\r\nConnection: close\r\n\r\n"
        )
        active.sendall(req.encode())
        buf = b""
        while len(buf) < 70000:
            chunk = active.recv(8192)
            if not chunk:
                break
            buf += chunk
        parsed = parse_http(buf)
        if parsed is None and cert is None:
            return None
        parsed = parsed or {"status": 0, "headers": {}, "cookies": [], "body": b""}
        parsed["cert"] = cert
        parsed["via"] = "https" if use_tls else "http"
        return parsed
    except (OSError, ssl.SSLError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe(ip: str, domain: str, timeout: float, path: str = "/") -> dict | None:
    hit = _exchange(ip, 443, domain, path, timeout, True)
    if hit and hit["status"]:
        return hit
    plain = _exchange(ip, 80, domain, path, timeout, False)
    if plain and plain["status"]:
        if hit and hit.get("cert") and not plain.get("cert"):
            plain["cert"] = hit["cert"]
        return plain
    return hit


def observation(hit: dict) -> dict:
    headers = hit["headers"]
    body = hit["body"]
    return {
        "status": hit["status"],
        "server": headers.get("server", ""),
        "location": normalize_location(headers.get("location", "")),
        "title": extract_title(body),
        "body_hash": md5(body),
        "cdn": cdn_providers(headers, hit["cookies"]),
        "cert": hit.get("cert"),
        "via": hit["via"],
        "cookies": [c.split("=", 1)[0].strip() for c in hit["cookies"]][:8],
    }


def score(fp: dict, obs: dict, trusted: bool) -> dict:
    signals = []
    fish1 = []
    if obs["status"] and obs["status"] == fp["status"]:
        signals.append({"id": "status", "weight": 1, "label": f"status {obs['status']}"})
        fish1.append(f"status:{obs['status']}")
    if fp["title"] and obs["title"] and fp["title"] == obs["title"]:
        signals.append({"id": "title", "weight": 4, "label": "title matches"})
        fish1.append("title_match")
    if fp["body_hash"] and obs["body_hash"] == fp["body_hash"] and fp["body_hash"] != EMPTY_MD5:
        signals.append({"id": "body", "weight": 5, "label": "body hash matches"})
        fish1.append("body_hash_match")
    if fp["server"] and obs["server"] and fp["server"] == obs["server"]:
        fish1.append(f"server:{obs['server']}")
        if not EDGE_SERVER.search(obs["server"]):
            signals.append({"id": "server", "weight": 2, "label": f"server {obs['server']}"})
    if fp["location"] and obs["location"] and fp["location"] == obs["location"]:
        signals.append({"id": "location", "weight": 3, "label": f"redirect {obs['location']}"})
        fish1.append("location_match")
    cert = obs.get("cert") or {}
    if cert.get("matches") and not cert.get("edge"):
        signals.append({"id": "cert", "weight": 6, "label": "certificate names the target"})
    weight = sum(s["weight"] for s in signals)
    on_edge = bool(obs["cdn"]) or bool(cert.get("edge"))
    if on_edge:
        call = "edge"
    elif weight >= 5:
        call = "confirm"
    elif weight >= 2:
        call = "weak"
    else:
        call = "reject"
    need = 1 if trusted else 2
    return {
        "signals": signals,
        "weight": weight,
        "fish2": call,
        "fish1": "confirm" if len(fish1) >= need else "reject",
        "fish1_signals": fish1,
    }


def load_cf(timeout: float) -> list[ipaddress.IPv4Network]:
    try:
        text = http_text(CF_IPS, timeout)
    except (urllib.error.URLError, TimeoutError, OSError):
        eprint("[!] Cloudflare range list unavailable; edge check falls back to ASN")
        return []
    nets = []
    for line in text.split():
        try:
            nets.append(ipaddress.ip_network(line.strip()))
        except ValueError:
            pass
    return nets


def in_cf(ip: str, nets: list[ipaddress.IPv4Network]) -> bool:
    if not ipv4_ok(ip):
        return False
    addr = ipaddress.IPv4Address(ip)
    return any(addr in net for net in nets)


def cymru(ip: str) -> dict | None:
    rev = ".".join(reversed(ip.split(".")))
    origin = doh(f"{rev}.origin.asn.cymru.com", "TXT")
    if not origin:
        return None
    parts = [p.strip() for p in origin[0].split("|")]
    if not parts or not parts[0].isdigit():
        return None
    asn = int(parts[0])
    named = doh(f"AS{asn}.asn.cymru.com", "TXT")
    name = named[0].split("|")[-1].strip() if named else ASN_NAME.get(asn, "")
    return {
        "asn": asn,
        "prefix": parts[1] if len(parts) > 1 else "",
        "cc": parts[2] if len(parts) > 2 else "",
        "name": name,
        "edge": asn in EDGE_ASNS or in_cf(ip, []),
    }


def describe(ip: str, nets: list[ipaddress.IPv4Network]) -> dict:
    info = cymru(ip) or {"asn": None, "prefix": "", "cc": "", "name": "", "edge": False}
    cf = in_cf(ip, nets)
    info["edge"] = bool(info["edge"] or cf or (info["asn"] in EDGE_ASNS if info["asn"] else False))
    info["cdn"] = "Cloudflare" if cf else (ASN_NAME.get(info["asn"]) if info["edge"] else None)
    info["ip"] = ip
    return info


def flatten_spf(domain: str, depth: int = 0, seen: set[str] | None = None) -> list[tuple[str, str]]:
    if depth > 4:
        return []
    if seen is None:
        seen = set()
    if domain in seen:
        return []
    seen.add(domain)
    out: list[tuple[str, str]] = []
    for txt in doh(domain, "TXT"):
        if "v=spf1" not in txt.lower():
            continue
        includes = []
        for token in txt.split():
            if token.startswith("ip4:"):
                cidr = token[4:]
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                out.append((cidr, domain))
            elif token.startswith("include:") or token.startswith("redirect="):
                host = token.split(":", 1)[-1].split("=", 1)[-1].rstrip(".")
                if host:
                    includes.append(host)
        for host in includes[:6]:
            out.extend(flatten_spf(host, depth + 1, seen))
    return out


def ct_names(domain: str) -> tuple[list[str], str | None]:
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    try:
        data = http_json(url, 6)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return [], "crt.sh did not answer. CT harvest skipped."
    names = set()
    if not isinstance(data, list):
        return [], "crt.sh returned an unexpected body."
    for entry in data:
        for line in str(entry.get("name_value") or "").splitlines():
            name = line.strip().lower().lstrip("*.").rstrip(".")
            if not name or name == domain or not name.endswith("." + domain):
                continue
            if not re.fullmatch(r"[a-z0-9.-]+", name):
                continue
            names.add(name)
            if len(names) >= 400:
                break
    def rank(name: str) -> tuple[int, int]:
        label = name[: -(len(domain) + 1)]
        head = label.split(".")[-1]
        return (0 if head in BYPASS else 1, len(name))
    ordered = sorted(names, key=rank)[:12]
    return ordered, None


def hackertarget(domain: str) -> tuple[list[tuple[str, str]], str | None]:
    url = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(domain)
    try:
        text = http_text(url, 8)
    except (urllib.error.URLError, TimeoutError, OSError):
        return [], "HackerTarget did not answer."
    if "error" in text.lower() or "API count" in text:
        return [], "HackerTarget rate limited."
    rows = []
    for line in text.splitlines():
        parts = line.split(",")
        if len(parts) != 2:
            continue
        host, ip = parts[0].strip(), parts[1].strip()
        if ipv4_ok(ip):
            rows.append((host, ip))
    return rows, None


def ripe_prefixes(asn: int) -> list[str]:
    try:
        data = http_json(RIPE_PREFIXES.format(asn=asn), 12)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        die(f"could not load prefixes for AS{asn}")
    rows = ((data.get("data") or {}).get("prefixes") or [])
    out = []
    for row in rows:
        prefix = row.get("prefix") if isinstance(row, dict) else None
        if prefix and ":" not in prefix:
            out.append(prefix)
    return out


def asn_of_domain(domain: str) -> tuple[str, dict]:
    ips = [ip for ip in doh(domain, "A") if ipv4_ok(ip) and is_public(ip)]
    if not ips:
        die(f"no public IPv4 for {domain}")
    info = describe(ips[0], [])
    if not info["asn"]:
        die(f"no ASN for {ips[0]}")
    return ips[0], info


def expand(cidrs: list[str], max_hosts: int) -> tuple[list[str], list[str]]:
    ips: list[str] = []
    notes: list[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            notes.append(f"bad CIDR {cidr}")
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        if net.prefixlen < 16:
            notes.append(f"skip {cidr} (broader than /16)")
            continue
        count = host_count(net)
        if count > max_hosts:
            notes.append(f"skip {cidr} ({count} hosts > --max-hosts {max_hosts})")
            continue
        ips.extend(str(ip) for ip in net.hosts())
    # preserve order, drop duplicates
    seen = set()
    uniq = []
    for ip in ips:
        if ip not in seen and is_public(ip):
            seen.add(ip)
            uniq.append(ip)
    return uniq, notes


def fingerprint_target(domain: str, timeout: float, nets: list[ipaddress.IPv4Network]) -> tuple[dict, list[dict]]:
    ips = [ip for ip in doh(domain, "A") if ipv4_ok(ip)]
    public = [ip for ip in ips if is_public(ip)]
    if not public:
        die("the name has no public IPv4 address")
    apex = [describe(ip, nets) for ip in public[:4]]
    fp = None
    for ip in public[:2]:
        hit = probe(ip, domain, timeout)
        if not hit or not hit["status"]:
            continue
        obs = observation(hit)
        fp = {
            "ip": ip,
            "via": obs["via"],
            "status": obs["status"],
            "server": obs["server"],
            "location": obs["location"],
            "title": obs["title"],
            "body_hash": obs["body_hash"],
            "cdn": obs["cdn"],
            "cookies": obs["cookies"],
            "cert": obs["cert"],
        }
        break
    if fp is None:
        die(f"could not fingerprint {domain}")
    return fp, apex


def harvest(domain: str, nets: list[ipaddress.IPv4Network], subs: list[str]) -> tuple[list[dict], dict[str, list[str]], list[str]]:
    rows: list[dict] = []
    named: dict[str, list[str]] = {}
    warnings: list[str] = []

    def add(ip: str, source: str, name: str, note: str) -> None:
        rows.append({"source": source, "name": name, "value": ip, "note": note})
        if is_public(ip):
            named.setdefault(ip, [])
            label = f"{source} {name}"
            if label not in named[ip]:
                named[ip].append(label)
            eprint(f"    [{source}] {name} → {ip}")
        else:
            eprint(f"    [{source}] {name} → {ip} (non-public, not probed)")

    for mx in doh(domain, "MX"):
        host = mx.split()[-1].rstrip(".")
        if not host:
            continue
        resolved = [ip for ip in doh(host, "A") if ipv4_ok(ip)]
        if not resolved:
            rows.append({"source": "MX", "name": host, "value": "", "note": "did not resolve"})
        for ip in resolved:
            add(ip, "MX", host, "named mail address" if is_public(ip) else "non-public, not probed")

    seen_spf = set()
    for cidr, src in flatten_spf(domain):
        if cidr in seen_spf:
            continue
        seen_spf.add(cidr)
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen >= 32:
            ip = str(net.network_address)
            add(ip, "SPF", src, "single SPF address")
        elif net.prefixlen < 16:
            rows.append({"source": "SPF", "name": src, "value": cidr, "note": "broader than /16, not a lead to sweep"})
            eprint(f"    [SPF] {cidr} from {src} (broader than /16, skipped)")
        else:
            rows.append({
                "source": "SPF",
                "name": src,
                "value": cidr,
                "note": f"lead only. FISH 1.1 would open about {host_count(net)} hosts",
            })
            eprint(f"    [SPF] {cidr} from {src} (lead only, not expanded)")

    for ns in doh(domain, "NS"):
        rows.append({"source": "NS", "name": ns.rstrip("."), "value": "", "note": "nameserver, not probed"})

    for prefix in subs:
        host = f"{prefix}.{domain}"
        for ip in doh(host, "A"):
            if ipv4_ok(ip):
                add(ip, "Bypass", host, "bypass name" if is_public(ip) else "non-public, not probed")

    names, warn = ct_names(domain)
    if warn:
        warnings.append(warn)
    for name in names:
        for ip in doh(name, "A"):
            if ipv4_ok(ip):
                add(ip, "CT", name, "certificate-log name" if is_public(ip) else "non-public, not probed")

    ht, ht_warn = hackertarget(domain)
    if ht_warn:
        warnings.append(ht_warn)
    for host, ip in ht:
        if ipv4_ok(ip):
            add(ip, "PassiveDNS", host, "HackerTarget" if is_public(ip) else "non-public, not probed")

    return rows, named, warnings


def confirm_one(ip: str, domain: str, fp: dict, timeout: float, sources: list[str], trusted: bool) -> dict:
    hit = probe(ip, domain, timeout)
    if not hit or (not hit["status"] and not hit.get("cert")):
        return {
            "ip": ip,
            "sources": sources,
            "via": "none",
            "status": None,
            "server": "",
            "location": "",
            "title": "",
            "cert": None,
            "score": {"signals": [], "weight": 0, "fish2": "reject", "fish1": "reject", "fish1_signals": []},
        }
    obs = observation(hit)
    scored = score(fp, obs, trusted)
    return {
        "ip": ip,
        "sources": sources,
        "via": obs["via"],
        "status": obs["status"] or None,
        "server": obs["server"],
        "location": obs["location"],
        "title": obs["title"],
        "cert": obs["cert"],
        "cdn": obs["cdn"],
        "score": scored,
    }


def run(args: argparse.Namespace) -> dict:
    domain = normalize_domain(args.target)
    started = time.time()
    timeout = args.timeout
    nets = load_cf(min(timeout, 8))
    fp, apex = fingerprint_target(domain, timeout, nets)
    providers = list(dict.fromkeys(fp["cdn"] + [a["cdn"] for a in apex if a.get("cdn")]))
    edge = any(a["edge"] for a in apex) or bool(fp["cdn"])

    mode_bits = [args.cf, bool(args.cidr), args.asn is not None, args.auto_asn]
    if not any(mode_bits):
        args.cf = True
        eprint("[*] no mode given — passive harvest (the 2.0 default). Pass --auto-asn or -c to sweep a range you name.")

    if args.auto_asn or args.asn is not None:
        if args.auto_asn:
            _ip, info = asn_of_domain(domain)
            asn = info["asn"]
            eprint(f"[*] {domain} → {_ip} AS{asn} {info['name']}")
            if asn in CF_ASNS:
                die(f"AS{asn} is Cloudflare — use -cf")
        else:
            asn = args.asn
        prefixes = ripe_prefixes(asn)
        eprint(f"[*] AS{asn} — {len(prefixes)} IPv4 prefix(es)")
        args.cidr = list(args.cidr or []) + prefixes

    subs = [] if args.no_subs else load_wordlist(args.wordlist)
    rows, named, warnings = ([], {}, [])
    if args.cf or not args.cidr:
        eprint(f"[*] passive harvest for {domain}")
        rows, named, warnings = harvest(domain, nets, subs)

    apex_set = {a["ip"] for a in apex}
    candidates = []
    for ip, sources in named.items():
        if ip in apex_set or not is_public(ip):
            continue
        info = describe(ip, nets)
        candidates.append({
            "ip": ip,
            "sources": sources,
            "edge": info["edge"],
            "asn": info["asn"],
            "name": info["name"],
        })
    candidates.sort(key=lambda c: len(c["sources"]), reverse=True)
    off_edge = [c for c in candidates if not c["edge"]][: args.max_confirm]

    sweep_ips: list[str] = []
    sweep_notes: list[str] = []
    if args.cidr and not args.cf:
        sweep_ips, sweep_notes = expand(args.cidr, args.max_hosts)
        # passive hits inside the sweep keep the trusted flag
    elif args.cidr and args.cf:
        extra, sweep_notes = expand(args.cidr, args.max_hosts)
        sweep_ips = [ip for ip in extra if ip not in apex_set]

    trusted_set = {c["ip"] for c in off_edge}
    jobs = [(c["ip"], c["sources"], True) for c in off_edge]
    for ip in sweep_ips:
        if ip in trusted_set or ip in apex_set:
            continue
        jobs.append((ip, ["sweep"], False))

    eprint(
        f"[*] fingerprint {fp['via']} {fp['ip']} status={fp['status']} "
        f"server={fp['server']!r} location={fp['location']!r}"
        + (f" title={fp['title']!r}" if fp["title"] else "")
    )
    eprint(f"[*] probing {len(jobs)} address(es)  [concurrency={args.concurrency}]")

    confirms = []
    if jobs:
        with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
            futs = [
                pool.submit(confirm_one, ip, domain, fp, timeout, sources, trusted)
                for ip, sources, trusted in jobs
            ]
            for fut in as_completed(futs):
                confirms.append(fut.result())
    confirms.sort(key=lambda row: (-row["score"]["weight"], row["ip"]))

    strong = [c for c in confirms if c["score"]["fish2"] == "confirm"]
    weak = [c for c in confirms if c["score"]["fish2"] == "weak"]
    elapsed = round(time.time() - started, 2)

    fish1_hosts = 0
    fish1_cidrs = set()
    for ip in named:
        if is_public(ip):
            fish1_cidrs.add(slash24(ip))
    for row in rows:
        if row["source"] == "SPF" and row["value"]:
            try:
                net = ipaddress.ip_network(row["value"], strict=False)
            except ValueError:
                continue
            if net.prefixlen >= 16:
                fish1_cidrs.add(str(net if net.prefixlen < 32 else ipaddress.ip_network(f"{net.network_address}/24", strict=False)))
    for cidr in fish1_cidrs:
        fish1_hosts += host_count(ipaddress.ip_network(cidr))

    if strong:
        verdict, title = "origin", "Origin candidate"
    elif weak:
        verdict, title = "lead", "Weak lead only"
    elif edge:
        verdict, title = "edge", "Edge, origin not confirmed"
    else:
        verdict, title = "exposed", "Apex looks direct"

    report = {
        "tool": "fish2",
        "version": __version__,
        "target": domain,
        "verdict": verdict,
        "verdict_title": title,
        "elapsed_s": elapsed,
        "fingerprint": {k: v for k, v in fp.items() if k != "cert"} | {
            "cert_subject": (fp.get("cert") or {}).get("subject", ""),
            "cert_match": bool((fp.get("cert") or {}).get("matches")),
        },
        "apex": [{k: a[k] for k in ("ip", "asn", "name", "prefix", "cc", "edge", "cdn")} for a in apex],
        "providers": providers,
        "harvest": rows,
        "candidates": candidates,
        "results": confirms,
        "confirms": [c["ip"] for c in strong],
        "leads": [c["ip"] for c in weak],
        "fish1_would_open": fish1_hosts,
        "fish2_probed": len(jobs),
        "sweep_notes": sweep_notes,
        "warnings": warnings,
    }
    return report


def load_wordlist(path: str | None) -> list[str]:
    if not path:
        return list(BYPASS)
    try:
        with open(path, encoding="utf-8") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError as exc:
        die(f"wordlist: {exc}")
        return []


def emit(report: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2))
        return
    print(f"[=] {report['verdict_title']}  [{report['elapsed_s']}s]")
    print(f"    FISH 1.1 would open ~{report['fish1_would_open']} hosts. FISH 2 probed {report['fish2_probed']}.")
    held = [c for c in report["candidates"] if c["edge"]]
    if held:
        print("    held as edge: " + ", ".join(c["ip"] for c in held))
    for note in report["sweep_notes"]:
        print(f"    [skip] {note}")
    for warn in report["warnings"]:
        print(f"    [warn] {warn}")
    shown = [r for r in report["results"] if r["score"]["fish2"] in ("confirm", "weak", "edge")]
    if not shown:
        print("    no off-edge confirm and no weak lead")
    for row in shown:
        sc = row["score"]
        labels = ", ".join(s["label"] for s in sc["signals"]) or "no signal"
        flag = {"confirm": "+", "weak": "~", "edge": "-", "reject": " "}[sc["fish2"]]
        fish1 = "1.1-confirm" if sc["fish1"] == "confirm" else "1.1-reject"
        cert = ""
        if row.get("cert"):
            cert = f" cert={row['cert'].get('subject') or '-'}"
            cert += " match" if row["cert"].get("matches") else ""
        print(
            f"[{flag}] {row['ip']}  {sc['fish2']} weight={sc['weight']}  {labels}"
            f"  status={row['status']} {fish1}{cert}"
        )
        if row["sources"]:
            print(f"    {', '.join(row['sources'])}")


def self_test() -> None:
    fp = {
        "status": 200, "server": "nginx", "location": "", "title": "Home",
        "body_hash": "abc", "cdn": [],
    }
    weak = score(fp, {
        "status": 200, "server": "apache", "location": "", "title": "",
        "body_hash": "zzz", "cdn": [], "cert": None,
    }, True)
    assert weak["fish2"] == "reject" and weak["weight"] == 1 and weak["fish1"] == "confirm", weak
    strong = score(fp, {
        "status": 404, "server": "apache", "location": "", "title": "",
        "body_hash": "nope", "cdn": [],
        "cert": {"matches": True, "edge": False},
    }, True)
    assert strong["fish2"] == "confirm" and strong["weight"] == 6, strong
    veto = score(fp, {
        "status": 200, "server": "nginx", "location": "", "title": "Home",
        "body_hash": "abc", "cdn": ["Cloudflare"], "cert": None,
    }, True)
    assert veto["fish2"] == "edge" and veto["fish1"] == "confirm", veto
    empty = score(
        {"status": 200, "server": "", "location": "", "title": "", "body_hash": EMPTY_MD5},
        {"status": 404, "server": "", "location": "", "title": "", "body_hash": EMPTY_MD5, "cdn": [], "cert": None},
        True,
    )
    assert empty["weight"] == 0, empty
    assert dns_name_matches("*.example.com", "www.example.com")
    assert not dns_name_matches("*.example.com", "example.com")
    assert is_public("8.8.8.8")
    assert not is_public("10.1.1.1")
    assert not is_public("203.0.113.10")
    assert normalize_location("https://example.com/a?b=1") == "/a?b=1"
    ips, notes = expand(["203.0.113.0/24", "10.0.0.0/30", "1.2.3.0/8"], 100)
    assert ips == [] and notes
    print("self-test ok")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fish2",
        description="FISH 2 — origin IP discovery. Weighted confirm, no implicit /24 sweep.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  fish2.py -t example.com
  fish2.py -t example.com -cf -o results.json
  fish2.py -t example.com --auto-asn --max-hosts 512
  fish2.py -t example.com -c 203.0.113.0/28
  fish2.py --self-test
""",
    )
    p.add_argument("-t", "--target", help="Hostname. No scheme.")
    p.add_argument("-c", "--cidr", action="append", default=[], help="CIDR to probe. Repeatable. Skips networks broader than /16 or larger than --max-hosts.")
    p.add_argument("--asn", type=int, help="Probe announced IPv4 prefixes for this ASN")
    p.add_argument("--auto-asn", action="store_true", help="Resolve the apex ASN and probe its prefixes")
    p.add_argument("-cf", action="store_true", help="Passive harvest. This is also the default when no mode is given.")
    p.add_argument("-w", "--wordlist", help="Bypass-name wordlist, one label per line")
    p.add_argument("--no-subs", action="store_true", help="Skip the bypass-name wordlist")
    p.add_argument("--concurrency", type=int, default=30, help="Parallel probes (default 30)")
    p.add_argument("--timeout", type=float, default=6.0, help="Per-probe timeout seconds (default 6)")
    p.add_argument("--max-hosts", type=int, default=2048, help="Refuse a single CIDR larger than this (default 2048)")
    p.add_argument("--max-confirm", type=int, default=32, help="Cap on named passive addresses to probe (default 32)")
    p.add_argument("-o", "--output", help="Write the JSON report to this file as well as stdout")
    p.add_argument("--json", action="store_true", help="Print JSON instead of the text report")
    p.add_argument("--self-test", action="store_true", help="Run the scoring checks and exit")
    p.add_argument("-V", "--version", action="version", version=f"fish2 {__version__}")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.self_test:
        self_test()
        return
    if not args.target:
        die("missing -t target")
    if args.concurrency < 1 or args.max_hosts < 1 or args.max_confirm < 1:
        die("concurrency, max-hosts, and max-confirm must be positive")
    report = run(args)
    text_json = bool(args.json or args.output)
    emit(report, args.json)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
        if not args.json:
            eprint(f"[*] wrote {args.output}")
    # silence unused in case of future text+file combo
    _ = text_json


if __name__ == "__main__":
    main()
