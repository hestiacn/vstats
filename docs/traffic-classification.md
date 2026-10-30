# Optional traffic classification

The native fix recognizes a bounded `Bytespider` marker before the mobile/tablet
robot exemption, preserving the `Bytespider/` history ID and display entry.
It also precedes other robots.pm rules (e.g. generic `spider`), so matching desktop/TV/wearable requests move to `Bytespider/`; other device detection, rules and accounting stay unchanged.
Other robots.pm markers inside mobile or tablet user agents remain subject to the existing exemption; this fix does not change them.
Owners of customized `robots.pm` files must merge its new `BytespiderRobotID`
helper too; without it the parser retains its previous behavior.

`tools/traffic-classify.pl` is an optional **offline request report** (Perl 5.20+,
core modules). No AWStats configuration/history reads, network/DNS, automatic
installation/schedule/publication/blocking. Native missing-UA/accounting semantics
differ; counts are not AWStats visits, sessions or human visitors.

## Run explicitly

From the checkout, supply one stable, nonoverlapping site snapshot:

```sh
perl tools/traffic-classify.pl --config tools/traffic-classification.example.json \
  --input access.snapshot.log --input-format combined --output report.json
perl tools/traffic-classify.pl --config site.json --input access.snapshot.jsonl \
  --input-format jsonl --output report.html --output-format html
```

Output: `json` (default) or static `html`, without scripts/resources. Supply all
four required options once; only paired `--snapshot`/`--attestation` repeat. No
stdin, autodetection, globs, compression or multi-log merge. Duplicate lines
count again; replay is deterministic without accumulated state.

The tool writes **0600** reports via a temporary file and atomic rename in an existing,
operator-controlled directory; hostile concurrent directory mutation is outside
contract. It refuses symlinks/nonregular outputs, missing parents and output path/inode
aliases to inputs. Fatal failure preserves the prior report; no report on stdout.
It refuses CGI even with empty `GATEWAY_INTERFACE`; keep outside web-executable paths.

Default output omits raw records; `--details` adds client IP, decoded UA/target,
host, timestamp, line index and labels. Keep private; apply retention to reports,
logs and evidence. Publication/exclusion adoption is a separate operator decision.

## Labels and behavior evidence

One actor per parsed, in-scope request:

* `verified_crawler`: registry marker plus covering provider evidence, subject
  to the trust limits below.
* `declared_crawler_or_tool`: configured/registry marker without successful
  verification. Headers are spoofable; tools can be human-operated.
* `unknown`: neither condition; neither verified human nor bot.

One page/hit, absent assets/referer, old/short/missing UA, errors or hosting IP
do not assign identity. Browser names are not built-in evidence; local markers
are operator-attested.

The default scanner heuristic requires **3 distinct probe paths from 2 active
families within 60 seconds**, inclusive. Precision and recall are unknown. A probe request is flagged iff it belongs to a qualifying
interval for its **literal IP and exact decoded nonempty UA**. All member probes,
including earlier ones, are flagged; nonprobes never are. Groups sort by time,
so semantic counts are permutation-invariant. Equivalent IP spellings remain
distinct group keys; shared IP/UA identifies no person or intent.

`merged_scanner_sequences`: union of overlapping inclusive qualifying spans
per group, not visitors. Actor/scanner counts overlap. Missing UA/hostname client
prevents grouping, counts as insufficient and retains independent actor evidence.

## Configuration

The example makes no absence/probe claims. Requires `schema_version: 1`; rejects
unknown/duplicate decoded keys, wrong types, disallowed nulls, fractional/exponent
numbers, negatives and inconsistencies **before opening the log**. JSON nesting
≤32. No operator regex/code, arbitrary identity CIDRs or live DNS. Module
`defaults()` governs runtime defaults; tests check guide/example consistency.

| Field | Behavior |
| --- | --- |
| `hosts` | Default `[]`: all parsed hosts. Otherwise an exact normalized allowlist; missing/out-of-scope hosts count separately. |
| `crawler_tokens` | Supplied array replaces defaults; empty is allowed. Registry markers still declare. Defaults: `Googlebot`, `Bytespider`, `bingbot`, `AhrefsBot`, `ClaudeBot`, `GPTBot`, `curl`, `Wget`, `python-requests`. |
| `probe_families` | Default `[]`; dated absence attestations below. |
| `site_references` | Default `[]`; legitimate-path exemptions below. |
| `scanner` | Defaults: `distinct_paths: 3`, `distinct_families: 2`, `window_seconds: 60`. Partial objects fill defaults. Positive integer families ≤ paths ≤ 2048; window ≤ 3600. |
| `verification` | Default `max_gap_seconds: 86400`, range 0–604800; single-snapshot time tolerance is zero. |
| `exclude` | Default `[]`; separate comparison only, below. |
| `limits` | Partial object may lower these hard maxima. UA/target caps cannot exceed line cap. |

| Limit | Default and hard maximum |
| --- | ---: |
| `input_bytes` | 67108864 |
| `line_bytes` | 16384 |
| `records` | 100000 |
| `groups` | 100000 |
| `ua_bytes` | 4096 |
| `target_bytes` | 8192 |

All thresholds, domains, continuity/resource bounds are **heuristic assumptions**,
not accuracy measurements or sample sizes. Aggregate byte/record/group limits
are fatal. `records` includes nonblank malformed/oversized lines; groups include
complete parsed out-of-scope records. Per-record line/UA/target breaches discard
the row without truncation/matching, counted in `unparsed` with an `oversized`
subcount. Oversized whitespace also consumes record quota; ordinary blanks are
separate. The reader discards oversized lines in bounded chunks to the newline.
LF/CRLF terminate lines; one CR before LF belongs to the terminator, which
`line_bytes` excludes. UA/target sizes count decoded UTF-8 bytes.

Fixed bounds: config 1 MiB; 128 tokens of 1–64 ASCII bytes; 64 families; 2048 total
probe paths and 2048 references; 32 snapshots, each raw ≤2 MiB/attestation ≤16 KiB;
32768 total prefixes. JSONL schema/depth errors are unparsed; configuration or
provider errors are fatal. No parsed or no in-scope records is a nonzero failure.

Tokens are unique ignoring ASCII case and match `[A-Za-z0-9][A-Za-z0-9._-]*`.
Preceding character: absent or outside ASCII letters/digits. Following: `/`, `;`,
`)`, ASCII 0x09–0x0D/0x20, or end. Matching is ASCII-only case-insensitive;
`Byteſpider`/`XBytespider` do not match `Bytespider`. The finite local-token refusal
list is `Mozilla`, `Chrome`, `Safari`, `Firefox`, `Android`, `AppleWebKit`, `Mobile`,
`Version`, `Linux`, `Windows`, `Macintosh`, `Edg`, `Edge`, `OPR`, `Opera`; it is not
a complete browser catalogue. Supply explicit crawler/tool markers only.

### Probe evidence

Family keys: `id`, `paths`, `absent_from`, `absent_until`. IDs uniquely match
`[a-z][a-z0-9_-]*` (1–32 ASCII bytes); paths are a nonempty literal array. Periods: ordered inclusive integer UTC epochs 0–4102444800. Absence must cover
the **entire parsed input period**, including out-of-scope hosts, or the family
is inactive with a reported reason. Status cannot establish absence. Duplicate
paths or membership in two families are errors.

Reference keys: `path`, `from`, `until`. Duplicate reference paths are errors.
Any period overlap exempts that path for the whole run, even alongside an absence
claim. Use site inventory/reference evidence; ordinary content/assets/login/API
endpoints do not become probes just by returning errors. This fragment shows
synthetic shape, **not evidence about a real site**:

```json
{
  "probe_families": [
    {"id":"environment","paths":["/.env","/config.php"],"absent_from":0,"absent_until":1000},
    {"id":"git","paths":["/.git/config"],"absent_from":0,"absent_until":1000}
  ],
  "site_references": [{"path":"/config.php","from":100,"until":160}]
}
```

Targets strip literal query/fragment, then percent-decode once. Matching is
case-sensitive and preserves trailing slash. Only `/`-leading origin-form ASCII
paths qualify. Refused: absolute/authority/`*` forms, leading/interior double
slashes, dot segments, backslashes, controls/NUL, non-ASCII, invalid percent,
encoded slash/backslash, decoded `?`/`#`, residual `%`. Space is allowed, including
`%20` decoding. Unsupported targets retain actor/counts but cannot match probes.
Configured paths must already equal normal form.

## Input formats and host separation

Exactly NCSA `common` or `combined` fields:

```text
client ident auth [dd/Mon/yyyy:HH:MM:SS +/-HHMM] "METHOD target HTTP/x.y" status bytes
client ident auth [dd/Mon/yyyy:HH:MM:SS +/-HHMM] "METHOD target HTTP/x.y" status bytes "referer" "UA"
```

Separators are space/tab, method ASCII letters, status 100–599, bytes `-` or
nonnegative decimal. Validate calendar/offset and supported UTC epoch range
0–4102444800; leap seconds are refused. Quoted fields decode once: `\"`, `\\`,
`\xHH`, `\b`, `\n`, `\r`, `\t`, `\v`, per Apache
[`ap_escape_logitem`](https://github.com/apache/httpd/blob/2.4.x/server/util.c).
Other escapes/invalid UTF-8 are unparsed. UA is not percent-decoded. Common has
no UA; combined `"-"`/`""` means missing. Neither format has Host: aliases are
inseparable, and configured `hosts` makes such records host-missing rather than
silently assigning a site.

JSONL requires integer UTC-epoch `timestamp`, nonempty string `client`, string
`target`. Optional `user_agent`/`host` are strings or null; unknown keys are
unparsed. Null/empty UA is missing; `"-"` is literal in JSONL.

```json
{"timestamp":100,"client":"192.0.2.1","target":"/","user_agent":"Bytespider;","host":"example.test"}
```

Hosts ASCII-lowercase and remove one terminal dot: 1–253 bytes, dot-separated
1–63-byte labels matching `[a-z0-9]([a-z0-9-]*[a-z0-9])?`. IP literals, ports,
brackets, underscores, empty strings/non-ASCII are invalid; IDNs use A-labels.
Invalid JSONL hosts are unparsed; invalid configured hosts fail validation.
Client hostnames retain actor evidence without resolution; verification/scanning
require literal IP. IPv4-mapped IPv6 stays IPv6; acceptance
follows platform `inet_pton`.

## Offline provider evidence

Initial registry: `google_common` / `Googlebot`, using Google's
[common-crawler ranges](https://developers.google.com/static/crawling/ipranges/common-crawlers.json).
[Google's guidance](https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests)
distinguishes common, special-case and user-triggered publications. Registry changes require review; no operator CIDR/ASN identity verification.

Pair unmodified raw provider JSON with an attestation:

```json
{"provider_id":"google_common","source_url":"https://developers.google.com/static/crawling/ipranges/common-crawlers.json","retrieved_at":"2026-10-30T10:00:00Z"}
```

```sh
perl tools/traffic-classify.pl --config site.json --input access.jsonl \
  --input-format jsonl --output report.json \
  --snapshot ranges-before.json --attestation before.json \
  --snapshot ranges-after.json --attestation after.json
```

Pairs are positional/equal in count. Provider keys: `creationTime` (string),
nonempty `prefixes`; each entry exactly one `ipv4Prefix`/`ipv6Prefix`. Validate
family, length and zero host bits. Invalid/empty/mismatched data or duplicate
retrieval times fails before log reading. Report raw SHA-256, provider/source,
retrieval time, provider creationTime and trust.

**Origin authenticity is operator-attested.** Hash/format/registered URL do not
authenticate source; creationTime is provider data, not period proof. For request
t choose nearest supplied snapshots at/before and at/after t. Both must contain
the client, gap ≤ `max_gap_seconds`; one snapshot suffices only at exactly t.
Bracketing assumes continuity, not uninterrupted ownership proof. Verification
is labelled **verified against operator-attested published-range snapshots**.

Covering evidence missing the IP in either bracket yields `failed`; absent or
too-distant evidence/nonliteral client yields `unavailable`. Both retain declared
identity. IPv4 prefixes do not cover mapped IPv6 unless separate IPv6 ranges do.
Historical replay needs archived
covering evidence; current ownership cannot verify past requests.

## Counts and adoption

Schema 1: algorithm/config/input digests, effective rules, period, host policy,
provenance, limitations. Identities:
`lines_total = blank + unparsed + parsed` and
`parsed = host_missing + out_of_scope + analyzed`. Actor/verification sums each
equal analyzed requests. Unsupported targets, insufficient fields, scanner
requests and merged sequences are separate.

`exclude` accepts only `declared_crawler_or_tool`, `verified_crawler`,
`scanner_flagged`. A separate **requests in this input excluding <categories>**
comparison shows original/excluded/remaining counts and config hash. Subtract
the per-request union once. `unknown` cannot be selected as actor, but its requests
can independently be scanner-flagged. Remaining counts never claim humans or
AWStats visitors.

Before exclusions, set a false-positive/evaluation criterion and check known
ordinary browsing, authorized tools and supported crawlers. Legitimate browsing
satisfying the heuristic requires revisiting it before adoption.

## Tests and packaging

```sh
prove -Itools/lib tools/t/*.t
```

Portable tests: strict inputs, independent interval/CIDR oracles, hostile reports,
CLI file/privacy behavior. Optional full-parser tests skip with reasons if
JSON::XS, Try::Tiny or Geo::IPfree is missing. These are parser dependencies, not
companion dependencies. No private compatibility module ships.
The full test covers a helper-less database; native auto-requested geoipfree
is unchanged.

The source packager recursively copies `tools/`/`docs/`. Release workflows are
unchanged; generated RPM/DEB/other packages were not validated. Test the checkout.
