# ip-radar-blocklist

Daily tiered IP blocklist generated from the
[ip-radar](https://github.com/steponeerror/ip-radar) threat-intelligence engine —
44 sources, consensus verdicts, all evidence recomputed before export.

> ip-radar 威胁情报引擎的每日阶梯黑名单导出：44 源聚合、全源共识判定，供防火墙 / fail2ban / 研究直接取用。

## Download

Each day's export is published as a [GitHub Release](releases) with all tiers attached as assets.

**Always-latest URL** (CDN-backed, stable):

```
https://github.com/steponeerror/ip-radar-blocklist/releases/latest/download/top_100.txt
```

Swap `top_100` for `top_500` / `top_1000` / `top_5000` / `top_10000`, or `.csv` for the enriched format.

## Files

| File | Content |
|---|---|
| `top_100.txt` … `top_10000.txt` | Pure list: one IP or CIDR per line (IPv4 + IPv6 mixed) |
| `top_100.csv` … `top_10000.csv` | Same entries with full context (9 columns) |
| `manifest.json` | generated_at, per-tier row counts, pool size, run stats |

Tiers are nested: `top_100 ⊂ top_500 ⊂ top_1000 ⊂ top_5000 ⊂ top_10000`.
Each tier always exists and holds up to its size ("up to N" — row count is the
honest signal). Updated daily.

## CSV columns

```
ip,asn,country,classes,confidence,source_count,sources,first_seen,last_seen
```

- `ip` — single IP or CIDR, exactly as recorded by the engine
- `classes` — threat categories (`;`-joined, e.g. `brute-force;scanner`)
- `confidence` — engine consensus confidence, 0–100
- `source_count` / `sources` — how many independent sources flagged it, and which
- `first_seen` / `last_seen` — earliest / latest observation across sources (may be empty)

Entries are ranked by **source_count ↓, confidence ↓, recency ↓** — the top of
`top_100` is the most heavily corroborated malicious infrastructure.

## Selection

An IP/CIDR enters the list only when the engine's fused consensus verdict is
**malicious** (suspicious-only entries are excluded). No aggregation, no range
expansion — units are exported at the granularity the sources recorded them.

## Usage

```bash
# fetch latest
curl -fsSL -o blocklist.txt \
  https://github.com/steponeerror/ip-radar-blocklist/releases/latest/download/top_1000.txt

# ipset (iptables)
ipset create ipradar hash:net
ipset restore < blocklist.txt
iptables -I INPUT -m set --match-set ipradar src -j DROP
```

For fail2ban, point an `ipset`-backed action at the same URL.

## License

The export is a consensus-derived dataset recomputed from all source evidence
and treated as new data — no redistribution restrictions.
