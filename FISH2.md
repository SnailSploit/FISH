# FISH 2

Origin IP discovery behind a CDN or reverse proxy.

**Fingerprint → Inspect → Harvest → Confirm**

Author: Kai Aizen / [SnailSploit](https://snailsploit.com)
Version: 2.0.0

`fish_scan.py` is FISH 1.1. `fish2.py` is the stricter tool. Stdlib only. Python 3.9+.

## What changed from 1.1

| | 1.1 | 2.0 |
|---|---|---|
| Confirm rule | 1 unweighted signal on a passive IP, 2 on a blind sweep | Weight ≥ 5. Status is 1, server 2, redirect path 3, title 4, body 5, certificate name 6 |
| Edge headers | Ignored. A Cloudflare answer can score as the origin | `cf-ray`, CloudFront, Akamai, Fastly, Imperva, Sucuri, Vercel, Netlify veto the match |
| TLS to a raw IP | Skipped. Certificate check stalled the probe | Connected with the real hostname as SNI. The certificate is evidence |
| One mail IP | Expanded to a `/24` (254 hosts) | That address only. An SPF network is printed as a lead and not swept |
| Default with just `-t` | Required a mode | Passive harvest |
| Dependencies | `httpx`, `dnspython`, `beautifulsoup4` | None |
| Prefix source | BGPView | RIPE Stat announced prefixes |
| Large CIDR | Skip broader than `/16` | Also skip a prefix bigger than `--max-hosts` (default 2048) unless you raise it |

A shared `200` is not a confirm. FISH 1.1 would print it as one.

## Usage

```
python3 fish2.py -t TARGET [options]
```

```
python3 fish2.py -t example.com
python3 fish2.py -t example.com -cf -o results.json
python3 fish2.py -t example.com --auto-asn --max-hosts 512
python3 fish2.py -t example.com -c 203.0.113.0/28
python3 fish2.py --self-test
```

No mode means `-cf`: MX, SPF, certificate-log names, the bypass wordlist, and HackerTarget. Named public addresses that are not the apex and not a known edge ASN are probed. At most `--max-confirm` (default 32).

`--auto-asn` and `--asn` and `-c` probe the ranges you named. Prefixes broader than `/16` are skipped. A prefix whose host count exceeds `--max-hosts` is skipped whole, not sampled. Cloudflare ASNs still refuse `--auto-asn`; use `-cf`.

Private, loopback, link-local, shared (100.64/10), and documentation ranges are not probed.

## Output

`+` confirm, `~` weak lead, `-` still on an edge. The `1.1-confirm` tag is what the old unweighted rule would have done with the same response.

`--json` prints the report. `-o file` writes it.

## Weights

| Signal | Weight | Counts when |
|---|---|---|
| status | 1 | Same status code |
| server | 2 | Same `Server`, and it is not a CDN banner |
| redirect path | 3 | `Location` path matches, scheme and host stripped. Redirects are not followed |
| title | 4 | Same non-empty `<title>` |
| body | 5 | Same MD5, empty bodies ignored |
| certificate | 6 | Peer certificate names the target and the issuer is not the edge |

Edge headers on the probe force `edge` no matter the weight.

## Scope

Run it against a host you are authorized to assess. It does not expand a passive address into a network. A CIDR is probed only when you pass `-c`, `--asn`, or `--auto-asn`.
