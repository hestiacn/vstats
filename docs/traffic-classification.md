# Optional traffic classification

## Suspected automation from request behavior

The optional `behavior` configuration adds an independent `suspected_automation`
flag. It uses no geography, country, ASN, provider ownership or current DNS.
Actor identity and existing scanner flags are preserved, and counts overlap.
It is disabled by default; enable it explicitly for a report:

```json
{"schema_version":1,"behavior":{"enabled":1}}
```

Starter defaults are `enabled: 0`, `window_seconds: 60`, `min_requests: 60`,
`distinct_user_agents: 4`, `distinct_platforms: 2`, `distinct_paths: 10`,
`not_found_requests: 10`. These are exploratory heuristic assumptions, not
calibrated cutoffs or measured accuracy. A partial object fills defaults.
All enabled runs report the effective settings, eligible/insufficient request
counts, qualifying request union, merged sequences and overlapping actor counts.

All criteria must hold together in the same inclusive rolling window, grouped
by literal client IP and normalized host, deliberately across user agents.
Equivalent textual IPv6 addresses share a behavior group; IPv4-mapped IPv6
remains separate from IPv4, matching the existing verification policy.
Requests are time-sorted before evaluation. Only eligible requests inside a
qualifying window are flagged; the rest of an IP's traffic is not relabelled.
Hostless logs retain their inseparable-alias limitation. Identical input records
count separately; operators must avoid overlapping or duplicated source files.

Eligible records need a literal client IP, supported normalized target, HTTP
status and a recognized browser/platform claim. Browser markers are bounded
`Chrome/`, `CriOS/`, `Firefox/`, `FxiOS/`, `Safari/`, `Edg/`, `OPR/`, `Opera/`;
platform categories are iOS, Android, Windows, Mac and Linux, in that priority.
They describe user-agent claims, not authenticated hardware or identities.
Apache combined input supplies the status; common input lacks a user agent and
cannot qualify. JSONL accepts an optional integer `status` from 100 through 599.
Omitting it retains actor classification but cannot support this behavior flag.
404 counts are evidence of the configured pattern, never proof that a site
component is absent. Missing referrers or asset requests are not triggers.

`enabled` must be integer 0 or 1. The window is 1–3600 seconds; minimum requests
is 2–100000, user-agent diversity is 2 through that minimum, platform diversity
is 2–5 and cannot exceed user-agent diversity. Path diversity is 2–2048 and
cannot exceed minimum requests; the required 404 count is 2 through minimum
requests. Existing record/group/byte/field caps remain, including a group cap
for behavior's IP/host keys. Window maintenance is linear after time sorting;
it does not enumerate all intervals or evaluate operator regexes.

Shared proxies can mix real users, authorized tests can be automated and browser
claims can be forged. Precision/recall are unmeasured. Input partition boundaries
can miss a window that crosses them; daily reports must disclose that limitation.
Evaluate against known ordinary site traffic before adopting exclusion policies.
This flag is not a verified crawler identity or a request-blocking rule. It
changes no history by itself. An explicit `suspected_automation` exclusion can
now export filtered input for a separately maintained native AWStats view.
The native verified-crawler option still requires supported identity and dated
provider evidence; behavioral selection is a separate operator policy.

Reports retain schema 1 with additive behavior fields; algorithm identity is
`vstats-traffic-v8`. Optional private details include status, the per-request
behavior flag, request ID, normalized query-free path, inclusion/exclusion state
and a numeric witnessing window. Aggregate JSON/HTML contains no source IP, target or user-agent
records. HTML shows behavioral counts separately from actor identity.

### Configured endpoint probing

The separate optional `probing` rule detects concentrated requests to
operator-configured endpoints together with rotating browser and platform
claims. It is generic: configure the endpoints relevant to your application,
including authentication, administrative, API or diagnostic routes. These are
positive points of interest, not absence attestations. Existing endpoints and
HTTP 200 responses can participate; status does not establish authentication
success, failed login attempts or malicious intent.

```json
{
  "schema_version": 1,
  "probing": {
    "enabled": 1,
    "paths": ["/account/sign-in", "/api/users"]
  },
  "exclude": ["suspected_automation"]
}
```

Defaults are `enabled: 0`, `window_seconds: 60`, `min_requests: 30`,
`distinct_user_agents: 4`, `distinct_platforms: 2`, `paths: []`. These are
exploratory heuristic starter settings, not calibrated accuracy thresholds.
Enabling this rule requires a nonempty list of unique normalized exact paths.
Query strings are stripped from observed targets; configuration paths cannot
contain queries, fragments, unsupported normalization or duplicates. There are
at most 2048 paths, each within the configured target-field byte cap. Volume,
window and browser/platform bounds match the corresponding `behavior` fields.

All criteria must coincide in an inclusive window for a canonical literal IP
and normalized host. Only eligible requests to the configured exact paths
contribute to the window or receive its flag. Other requests from that same
source, including ordinary pages and assets between probes, remain outside
this rule. No path-diversity or 404 minimum is required. A stable browser,
multiple unrelated sources, a single platform, an isolated endpoint request
or missing browser/status fields cannot independently satisfy it. It does
not identify every kind of probing; fixed-agent probes need other evidence.

### Sustained endpoint probing

The existing endpoint rule can also detect slower repeated activity by setting
its independent `window_seconds`, for example `900`, while retaining the
configured paths, volume and browser/platform diversity tests. The short
60-second default remains available. A longer window is an exploratory
operator choice: it increases sensitivity and can pool more legitimate users
behind a shared IP. It does not establish failed logins, credentials, intent or
authentication outcomes; all conditions must still coincide in a real window.

### Rapid content-path probing without browser rotation

The independent optional `rapid_scan` rule detects rapid sweeps through many
content paths with repeated HTTP 404 responses. It requires neither a browser
claim nor variation across user agents/platforms. A stable agent or a common
log without user agents can therefore provide sufficient path/status evidence.

```json
{
  "schema_version": 1,
  "rapid_scan": {"enabled": 1},
  "exclude": ["suspected_automation"]
}
```

Defaults are `enabled: 0`, `window_seconds: 60`, `min_requests: 30`,
`distinct_paths: 20`, `not_found_requests: 10`. These are exploratory heuristic
starter settings, not calibrated precision/recall or a proof of maliciousness.
Volume, path diversity and actual 404 counts must hold together in the same
inclusive rolling window for one canonical literal IP and normalized host.
Only eligible requests in a qualifying window receive this request-level flag.
Out-of-window traffic and ordinary assets remain unflagged by this rule; the
separate IP/month policy can explicitly exclude their source traffic later.

A literal client IP, supported normalized target and HTTP status are required.
The rule ignores these conventional static asset suffixes (case-insensitive):
`css`, `js`, `mjs`, `cjs`, `map`, `png`, `jpg`, `jpeg`, `gif`, `webp`, `avif`,
`svg`, `ico`, `bmp`, `tif`, `tiff`, `woff`, `woff2`, `ttf`, `otf`, `eot`, `mp3`,
`mp4`, `webm`, `ogg`, `wav`, `pdf`, `zip`, `gz`, `br`, `rar`, `7z`, `tar`.
They contribute neither volume, path diversity nor errors, even during a scan.
This deliberately leaves scans limited to these assets undetected. No path is
claimed absent from the site; 404 is observed response evidence only. Failed
page prefetches, broken applications, shared proxies or authorized scans can
qualify. Inspect the numeric witness and use inclusion overrides when needed.

`enabled` is integer 0 or 1; the window is 1–3600 seconds; minimum requests is
2–100000; distinct paths is 2–2048 and cannot exceed minimum requests; the 404
minimum is 2 through minimum requests. Partial objects fill defaults. The
existing byte, record, field and canonical IP/host group caps still apply.
Window maintenance is linear after sorting; no operator regex/code is executed.
All four behavioral rules remain optional and independently configurable.

`suspected_automation` is the union of enabled broad path probing, configured
endpoint probing, rapid content-path probing and distributed login probing. Actor identities and the absence-attested `scanner_flagged`
layer remain independent. An overlapping request counts once and retains every
applicable covering witness in private details and curated review. Aggregate
`behavior` contains `broad_rule`, `probing_rule`, `rapid_scan_rule`, `distributed_login_rule`,
`broad_flagged_requests`, `probing_flagged_requests`,
`rapid_scan_flagged_requests`, `distributed_login_flagged_requests` and `overlap_requests` (requests matching at least
two rules); its main request and actor
counts are the union. Eligible and insufficient-field counts deduplicate records
across enabled rules. Merged sequence counts sum the rules' sequences, which may
overlap and are not visits. Effective configuration includes the operator's
endpoint list; aggregate output contains no observed request records.

Private details include `broad_probing_flagged`, `probing_flagged`,
`rapid_scan_flagged`, `distributed_login_flagged`, `probing_evidence`,
`rapid_scan_evidence` and `distributed_login_evidence`, retaining the
existing broad `behavior_evidence`. Review
labels each applicable rule and its numeric covering window. The same explicit
exclusion selector and `behavior_include` request IDs apply to every rule;
inclusion retains all witnesses and cannot override independent actor/scanner
exclusions. All four rules are opt-in and may be enabled separately. Shared proxies
and authorized automation can qualify; review results before relying on them.

### Explicit filtering and inclusion overrides

```json
{
  "schema_version": 1,
  "behavior": {"enabled": 1},
  "exclude": ["suspected_automation"],
  "behavior_include": []
}
```

```sh
perl tools/traffic-classify.pl --config site.json --input access.log \
  --input-format combined --output report.json --filtered-log filtered.log
```

The optional `--filtered-log` requires a nonempty explicit exclusion selection.
It removes only selected physical records and preserves all other input bytes,
including blank/unparsed/out-of-scope records and line endings. The second
bounded pass must match the classified input hash; otherwise export fails.
Input/output aliases, hardlinks between outputs and output symlinks are refused.
Both outputs are mode 0600. The report records original/filtered SHA-256 and log
byte/record accounting. These byte counts describe **log files**, not HTTP
bandwidth. Caller must check successful exit and the report's filtered digest
before use: two atomic renames are not a multi-file transaction.

`behavior_include` defaults to `[]`: up to 2048 unique lowercase 64-hex request
IDs. A request ID is SHA-256 of the raw logical log record, excluding LF and one
CR immediately before LF. Byte-identical duplicate records share an ID; an
override retains all such records. It suppresses only behavioral exclusion,
not independently selected actor/scanner exclusions, and retains the suspicion
flag/evidence for review. Lists are operator-controlled; copying an ID is not
itself a server-side change. Private details expose IDs and witnessing windows.

Use complete, nonoverlapping input to replay original rules, confirmed-only
rules and behavior-filtered rules into independent histories. Recompute native
visits and unique visitors; never subtract request counts from those metrics.
Explain which flagged records were already non-viewed under native rules.
Retain an unfiltered comparison and an explicit user choice of report view.
Provider snapshots must still cover request dates; use archived day-sized
bundles within existing evidence caps for historical native replay.

### Optional daily export and review builder

The native-report export excludes automated IPs **by default**. If any enabled
behavior rule flags a request, its canonical literal source IP is excluded
throughout the same UTC report month in the provided site corpus, including
earlier days. There is no carry-over to another month without new evidence.
This policy spans the accepted hosts/aliases in that site input; supply separate
site inputs when that is not the intended scope. It does not relabel every
request from that IP as independently detected automation or assert a verified
crawler identity. Classifier flags and actor identities remain unchanged.

AWStats must replay the selected requests into independent histories, so unique
visitors, visits, pages, hits and bandwidth stay internally consistent. Never
subtract source counts from native visitor totals. After replay, verify that
excluded source/months are absent from native visitor records unless an explicit
inclusion exception restored them. Shared proxies, dynamic addresses and
authorized automation can cause false positives.

Disable only IP expansion with `--include-automated-ips`, or call
`build(..., exclude_automated_ips=False)`. The request-level behavior filters
remain active. The standalone classifier/`--filtered-log` still classifies and
filters individual requests; it has no native visitor counter to change. The
corpus builder joins the daily evidence before applying its visitor policy.
Private details provide canonical `source_key`, `source_month` and
`source_month_key`; IPv4-mapped IPv6 remains distinct from IPv4.

Request-ID inclusion exceptions also apply to additional IP-policy exclusions.
They can intentionally restore that IP to visitor counts, retain the real
trigger evidence and do not clear its automation flag. A copied ID alone does
not change server settings. Unparsed, out-of-scope and unattributable records
are preserved; callers must audit native output rather than claim that malformed
input has been attributed safely.

With Python 3.6+ and a suitable Perl interpreter, the generic builder processes
an existing stable directory of `YYYY-MM-DD.log` combined-log partitions:

```sh
python3 tools/traffic-filter-report.py --config site.json \
  --input-directory /private/corpus --output-directory /private/new-result \
  --perl /path/to/perl --site-url-prefix /vstats/example.test/
```

It requires exactly `exclude: ["suspected_automation"]`, refuses an existing
output directory and writes private `filtered/`, `request-filtered/`, `reports/`, `classification/`,
`review/` directories and `summary.json`. Input partitions must match their UTC
dates. Detailed JSON stays private; curated HTML shows request IDs, query-free
paths, source IPs, HTTP status, restricted browser/platform claims and numeric
witnesses. Full raw user-agent strings are omitted. Only publish the HTML behind
the site's intended statistics access controls. Page size defaults to 200, with
range 1–1000; these are UI/resource heuristics, not sampling. Every flagged
record selected by a detector or the IP policy appears, including retained inclusion overrides.
IP-policy reasons name the report month and a real triggering request; the
trigger's window is not misrepresented as covering an unrelated request.
Bounded page navigation keeps every row reachable without quadratic link lists.
View links assume canonical default IP policy, `requests/` request-only filtering,
`confirmed/` behavior-off and `original/` original rules;
the operator must generate those independent native views.

The builder performs no network lookup, history modification or deployment.
`excluded_by_month.response_body_bytes` is a separate HTTP response-body ledger
(304 contributes zero), unlike the CLI's log-file byte counts. It includes
flagged requests that native rules may already treat as non-viewed. Compare
independently replayed native histories to measure changes to viewed totals.
Repeated report generation allows new inclusion overrides and changed windows
to affect past statistics; input retention and scheduling remain operator policy.

`request-filtered/` and each classifier JSON's `filtered_log` retain the
request-only selection. `filtered/` is the default visitor-policy input.
The private builder summary contains both stream manifests and body-byte ledgers:
`excluded_by_month` for the default input and `request_excluded_by_month` for the
request-only input. Each daily summary's `filtered_log` describes the default
stream and `request_filtered_log` its request-only comparison. All input hashes
are rechecked between passes. Per-month `ip_policy_sha256` binds the full set of
provided daily input identities, configuration, chosen policy and triggers.
The private `ip_exclusion` summary stores the trigger map, restored source/month
keys and separate counts; it must not be published as an aggregate report.
Curated review HTML remains subject to statistics access restrictions.

## Additional verified-crawler filtering in AWStats

`VerifiedCrawlerEvidenceFile="/private/path/evidence.json"` enables an additional
native check for HTTP NCSA combined (`LogFormat=1`) or common (`LogFormat=4`)
input. The default empty setting retains existing behavior. Common logs have no
user-agent marker and therefore cannot gain a verified crawler identity.

The additional layer uses the same `verified_crawler` identity rules as this
report. A supported crawler marker and covering provider evidence are both
required. A declaration, scanner flag, unknown label, missing evidence or failed
verification never creates an additional exclusion. Existing user-agent, worm,
error and other native classification rules continue to apply independently.
The current registry supports Google's common crawlers with the `Googlebot`
marker; other providers have not been added by this option.

Confirmed eligible requests enter native robot/non-viewed accounting before
download tracking, including valid 200/206 downloads and zero-byte 304 responses.
The parser performs no network or DNS lookup. Malformed or unreadable evidence
stops an update before history changes; unsupported individual records cannot
become verified exclusions.

The evidence file is a schema-1 bundle, capped at 64 MiB:

```json
{"schema_version":1,"snapshots":[{"raw_json":"UNMODIFIED_PROVIDER_JSON","attestation_json":"RETRIEVAL_ATTESTATION_JSON"}]}
```

Each string contains the corresponding UTF-8 JSON document defined below. The
existing per-document, snapshot-count, aggregate-prefix and time-gap limits
still apply. This bundle cap is an operational resource bound, not an accuracy
measurement. Retain evidence as a private operator-controlled file.

On POSIX hosts, the optional Python 3.6+ collector fetches only the registered
public HTTPS source, validates its format, records the actual retrieval time,
archives unmodified content by digest and atomically replaces the runtime bundle:

```sh
python3 tools/crawler-evidence.py --directory /private/path
```

It reads no visitor logs and sends no visitor addresses to the provider. Raw
content is deduplicated, retrieval attestations remain archived, and the runtime
bundle uses the latest evidence within the reviewed snapshot/prefix caps. HTTPS
verification is enabled; redirects away from the registered URL are refused.
Collection failures preserve the prior bundle. No schedule is installed by the
tool. Record collection after freezing the input snapshot so that its newest
request can be bracketed by an actual subsequent retrieval.

Retrieval times are never inferred from provider `creationTime`. The first
collection cannot verify older requests; current DNS or current IP ownership is
not retrospective evidence. A caller may continue with the prior valid bundle
after a collection failure, leaving uncovered requests under existing rules.

This native option affects newly processed records. It does not recalculate
existing history or prove that the remaining traffic is human. A report toggle
requires independent history directories for the original rules and the
additional layer, maintained against the same input and rendered separately.
Seed a new forward-looking layer from existing history before processing new
records, or replay a complete, nonoverlapping source corpus into a fresh history.
Do not subtract request labels from stored unique-visitor or visit counts.

The native fix recognizes a bounded `Bytespider` marker before the mobile/tablet
robot exemption, preserving the `Bytespider/` history ID and display entry.
It also precedes other robots.pm rules (e.g. generic `spider`), so matching desktop/TV/wearable requests move to `Bytespider/`; other device detection, rules and accounting stay unchanged.
See the named-crawler section below for other enabled literal crawler identities.
Owners of customized `robots.pm` files must merge the `BytespiderRobotID` and
`RegisteredCrawlerRobotID` helpers too; without a helper its corresponding
recognition keeps the previous behavior.

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
| `behavior` | Optional browser-rotation/path/404 rule; defaults and bounds above. |
| `probing` | Optional configured-endpoint/browser-rotation rule; independent window can cover sustained probing. |
| `rapid_scan` | Optional content-path/404 burst rule without browser requirements; defaults and asset exclusions above. |
| `verification` | Default `max_gap_seconds: 86400`, range 0–604800; single-snapshot time tolerance is zero. |
| `exclude` | Default `[]`; explicit comparison and optional filtered-log export, below. |
| `behavior_include` | Default `[]`; operator request-ID overrides for behavioral exclusions only. |
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
`scanner_flagged`, `suspected_automation`. A separate **requests in this input excluding <categories>**
comparison shows original/excluded/remaining counts and config hash. Subtract
the per-request union once. `unknown` cannot be selected as actor, but its requests
can independently carry scanner or behavioral flags. Remaining counts never claim humans or
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

### Explicit named crawlers and mobile/tablet claims

Native AWStats retains its existing Bytespider identity precedence. Before
applying the mobile/tablet exemption it also checks explicit, boundary-matched
literal identities from the enabled robot registry levels: named bot/spider/
crawler/scraper/robot tokens and the explicit `facebookexternalhit` and
`meta-externalagent` identities. Generic browser words, webview/client IDs and
nonliteral registry patterns do not receive this override. Literal entries contain
only ASCII letters/digits, dots, underscores or hyphens, with an optional final
slash; escaped registry patterns such as `Storebot\-Google/` are not eligible.
Bare generic bot/robot/spider/crawler/scraper tokens and the helper's enumerated
client-name collisions (including handset manufacturer CUBOT) do not override
the exemption. A mobile agent
that explicitly declares a registered crawler such as PetalBot therefore keeps
its existing robot history ID and non-viewed classification. Ordinary mobile
agents, disabled robot detection and older custom databases without the helper
retain their prior behavior. Desktop/device metadata and the order of ordinary
nonmobile registry matching are unchanged. This is unverified user-agent evidence;
it does not authenticate a crawler operator or expand the verified-IP registry.


## Distributed login probing (optional)

`distributed_login` is disabled by default. Enable it only after configuring exact
`login_paths` and `admin_paths` for the site. They must be disjoint normalized paths;
queries are discarded before matching. It uses HTTP methods from Apache logs or the
optional JSONL `method` string (1–32 ASCII letters, normalized uppercase). A missing
method is accepted but cannot support this rule. No request bodies, credentials,
cookies or authentication results are collected.

Defaults are heuristic assumptions, not calibrated detection accuracy:
`enabled: 0`, `window_seconds: 1800`, `min_requests: 30`, `min_sources: 3`,
`min_post_requests: 10`, `distinct_user_agents: 8`, `distinct_platforms: 2`,
`min_source_posts: 2`, `distinct_source_user_agents: 2`,
`distinct_source_platforms: 2`, `shared_user_agents: 1`,
`login_paths: []`, `admin_paths: []`.

A candidate campaign must meet all pooled thresholds inside one window, using only
participating literal-IP sources on the same host. Each source independently needs
repeated login POSTs, diversity in POST user-agent and platform claims, and an ordered
login POST followed by a GET to a configured login/admin path. It must share the
configured number of exact POST user agents with other surviving participants.
Iterative peer removal prevents rejected sources supplying shared-UA evidence.
Isolated logins, nearby visitors, unrelated paths and asset requests do not receive
the request-level flag. IPv6 spelling variants share a source; mapped IPv6 remains
separate from IPv4. There are no geography, ASN or IP-prefix rules.

A same-full-UA login POST followed by a login/admin GET within `window_seconds`
defines a coherent-flow span. Intersecting candidate windows abstain for that
source/host. An unrelated early span no longer exempts all later activity. Spans
use the earliest same-UA POST still within the window, are merged, and protect
both sides of a grid boundary. This safeguard covers ordinary admin sessions and
coherent shared-office flows in those windows; it does not prove humanity, and
bots can imitate it. Other behavior rules remain independent. HTTP status does
not establish authentication outcome. The existing whole-IP/month policy can
still remove an earlier legitimate session if another window qualifies for that
IP. Request-only comparison and request-ID inclusions remain the exceptions.

Windows use two UTC fixed grids of the configured width, offset by zero and half the
width rounded down. Their right edges are exclusive; a request belongs to at most
two windows. Sorting and at most two memberships per row bound processing; source
window and source/window group counts are each capped by `limits.groups`. Fixed
grids can still miss some otherwise similar sliding sequences. Independent input
partitions need boundary context to identify sequences across midnight. Requests are flagged once even when windows overlap; merged sequence
counts unite overlapping qualifying intervals per host. `qualified_windows` remains
separate from that merged count.

Private details retain `distributed_login_flagged`, `distributed_login_evidence`,
source contributions and opaque POST/follow-up witness IDs. Campaign POST diversity
counts are separate from this source's contribution in review HTML and copied
whole-IP triggers. Full user agents and queries remain private. The aggregate
`distributed_login_flagged_requests` overlaps other rules and the union counts each
request once. Existing request-ID inclusions, request-only comparison and optional
whole-IP/month expansion apply unchanged. Shared proxies, browser popularity,
authorized tests, sparse sources and bots imitating stable flows limit inference;
unknown traffic must not be described as verified human.


## Boundary evidence and slower campaigns

The generic distributed-login default remains `window_seconds: 1800`. Its maximum
is `21600` seconds, an execution/resource heuristic rather than a calibrated bot
threshold. Other rule windows keep their existing maximum. Operators can choose a
longer distributed window to capture slower repeated campaigns; all source,
sequence, peer-sharing and pooled requirements still apply. A longer window can
also enlarge coherent-flow protection and can both add and remove flags.

The library method `analysis_window($config)` returns the largest enabled rule
window, including scanner context. `add_context('before', $raw)` and
`add_context('after', $raw)` accept at most one side each, using the primary input
format and the same parser. Context must be disjoint from the primary parsed
period. Bytes, nonblank records and source/UA groups count against the combined
configured caps. Context farther than the maximum rule window from the actual
primary period is unused; `used_analyzed_records` makes this explicit.

The CLI exposes `--context-before FILE` and `--context-after FILE`. Context paths
participate in output/input alias checks. Primary physical line indices, input
hashes, counts, actor totals, filtered manifests, exclusion IDs and exported bytes
remain primary-only. Rule windows and witnesses can use context, so a witness's
request volume can exceed the primary report's analyzed count. Rule sequence
metrics count qualifying intervals touching primary records. `analysis_context`
binds each provided side's SHA-256, byte size and parser counts; `analysis_period`
records the used evidence period. Scanner absence attestations must cover used
context too. Context never supplies authenticated identity beyond existing
provider-evidence rules.

The Python builder constructs bounded halos from adjacent UTC-day files using the
validated Perl configuration. It exports each primary record exactly once and
keeps halo logs private. Missing neighbors supply no evidence. Unparseable halo
lines remain unavailable evidence; they do not become timestamped requests.

Each `daily_reports` entry exposes `analysis_context_sha256`, hashing the selected
before/after bytes and maximum window. A cached monthly replay must bind these
values in addition to primary daily input, evidence, source and configuration
hashes. The following month's first-day halo can change the previous month's
classification; invalidate that earlier month too. Appending records outside the
halo does not alter the prior day's boundary dependency. The IP-policy context
binding also includes halo identities (`context_binding_version: 2`); IP/month
scope and selection rules remain unchanged. No source carries an exclusion into
another month without a matching primary request witness in that month.

## Retained-source and campaign summaries

The restricted review index links to `retained-YYYY-MM-NNN.html`, grouping analyzed
requests by canonical source and UTC month. It shows total/retained/excluded
requests, retained actor labels, overlapping reason counts and numeric candidate
window examples. Reasons distinguish disabled/missing-field cases, unrelated
routes, coherent-flow protection, missing source repetition/diversity/follow-up,
peer-sharing gaps, pooled threshold gaps and explicit ID inclusions. These are
behavioral decisions: native crawler/error rules may still mark retained requests
non-viewed. Unknown and retained must never be presented as verified human.
Unattributable or unparsed input remains preserved outside literal-IP source rows.

`campaign-YYYY-MM-NNN.html` groups flagged primary contributions by witnessing
campaign/source. Pooled counts are separate from source contributions. Windows
can overlap, so campaign evidence is not an additive traffic total. The assigned
primary-request column accounts for each matched primary request once. Both
summaries remain static, paginated and escaped; they omit raw user-agent strings,
queries, credentials and private JSON/log transports. Copying an ID never writes
configuration. Existing Apache restrictions must protect all these HTML pages.

Private details add `distributed_login_diagnostics`, with at most two memberships
per eligible primary request. `source_review` contains exact source accounting and
assigned campaign counts for audits. Summary population and assigned primary
matches are checked against the classifier totals before publication.
