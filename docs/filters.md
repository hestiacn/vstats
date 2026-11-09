# Filters for static vstats reports

The optional static publisher adds a **Filters** menu beside Basic, Guide,
Reference, Integration and Developer. Native reports keep their existing layout;
filter settings, explanations, previews, comparisons and review tables are in
Filters. Settings affect statistics, not access to the website.

## Corpus-aware automation filters

These independently selectable components operate on the retained site corpus:

* **Compound scripted browsing** requires independent evidence classes in an
  exact-client/known-vhost/observed-UA episode: a rare, genuinely quoted browser
  claim plus a successful content burst, or an observed-empty claim plus a
  multi-family metadata fetch. Missing logging is never an empty claim.
* **Scheduled crawling** learns distinctive weekday/API/feed/font patterns
  across complete UTC weeks. The target week cannot corroborate itself.
  A homepage qualifies only when that same source and observed UA have their
  own witnessed sweep within the bounded linking interval. A shared browser
  string alone never excludes a homepage.
* **Bounded scanner inference** combines a recorded provider-specific DNS check
  with an exact, structurally non-browser client fingerprint corroborated
  across multiple associated addresses, a bounded distance from that check,
  and explicitly selected UTC months. This changes the default report when
  enabled. It is inference, not verified historical ownership or current
  membership. Review the Preview before enabling; refresh the authorized
  candidate observations before initial activation. Existing strict dated
  verification and the optional retrospective comparison remain separate.
* **Declared automation** uses curated explicit crawler/research-automation
  tokens. An arbitrary application product/contact string is insufficient;
  declarations remain unverified. The initial token list is empty.

New profiles/Reset check these choices. Selected months and curated tokens are
prerequisites; a checked rule can therefore be inactive. Parameters are under
Advanced. Positive same-UA navigation/asset continuity vetoes the new episode
rules. These rules never seed IP/month expansion or change existing actor
identity. Request-ID inclusions retain the selected heuristic matches.

An optional `scheduled_automation.aggressive_comparison=1` adds phase-linked
cohort candidates to the existing **Inferred/aggressive comparison** only.
It never changes the default report. Shared fingerprints/phases can include
unrelated users; inspect its separate review labels. Its initial value is `0`.

Geography, hosting networks, browser age, a single page, robots.txt alone and
missing assets/referrers are not independent bot witnesses. All new thresholds
are exploratory heuristics; precision/recall are unmeasured. Earlier logs
without trustworthy site/client/field provenance may be insufficient. The
normal report entry and native browser-update access rules are unchanged.

## Using it

* **Settings:** six families — Bot and tool signatures, Provider evidence,
  Probing and scanning, Automated browsing, Bounded scanner inference and
  Metadata requests. Advanced keeps each component and its thresholds; optional
  retrospective inference stays separate and off by default.
  New intended primary settings are checked by default.
  Existing managed settings are imported only after their replay identities are
  verified. Checked settings can be inactive: paths may need configuration,
  evidence may not cover the request period, or classifier input may be over a
  documented hard maximum. IP/month expansion is a separate policy which needs
  a qualifying behavioral trigger for that website and UTC month.
* **Impact & reprocessing:** Preview uses the applied and proposed profiles on
  the same frozen input and evidence. It publishes nothing. Apply & reprocess
  rebuilds all retained input with native AWStats accounting. Before values for
  an unverifiable legacy generation are unavailable, never assumed or zero.
  Missing or changed prior source coverage requires explicit acknowledgement.
  A new report contains only the input actually rebuilt; it carries no totals
  produced under different rules.
* **Review:** classified, excluded and retained requests, sources and campaigns;
  three generation-bound native comparisons; request-ID inclusions with a
  reason. Byte-identical duplicates share an ID. An inclusion retains those
  records from behavioral/IP-policy exclusions; it does not erase evidence or
  override independently selected native, verified-crawler or actor/scanner
  treatment. Copying an ID does not change settings.
* **History:** report/profile generation identities, processing actor and time,
  recent job outcomes, retained reports, and restoring known previous settings
  as pending edits. Restore requires a new rebuild against retained input.

The login browser rotation filter requires explicit exact login paths. It detects
repeated adjacent GET/POST pairs whose claimed platforms change within the pair,
including activity spread across a day. See [rule settings and limitations](traffic-classification.md#login-browser-rotation).
Reset uses the checked defaults and retains any
configured login paths. Preview the impact, then Apply & reprocess to publish.

HEAD path sweeps, sensitive-file probing and WordPress enumeration have separate
component controls and advanced settings; new profiles and Reset use checked
defaults. These rules use observed request
patterns, not source-IP lists or geography. Known self-declared monitoring and
enrichment agents use the existing Native crawler signatures checkbox. They do
not become verified crawler identities. [Rule details](traffic-classification.md#low-volume-scanning).

Anonymous history actors mean permitted browser access, not an authenticated identity.
Related rules share a main-page checkbox. Advanced keeps each component and its
parameters. A mixed checkbox means only some components are selected; clicking it
selects them all, while clicking a fully selected group clears them all. The
status summary describes the current report, even while settings are pending.
Question-mark help works on hover, keyboard focus or tap, including read-only
pages; Escape dismisses it without changing a setting. Parameter descriptions
give the units and the evidence each threshold bounds.

Native detection level 1 uses the common and generic tables. Levels 2 and 3 add
the same extended table. That inherited table matches desktop Windows NT 10.0
user agents, including Microsoft Edge on Windows, as robots/non-viewed apart
from the native download-file exemption. These signatures do not prove bot
identity. Choose the native level with that limitation in mind.

The filtering PR and its detector extension are intended to ship together as
one feature. There is no upgrade path between their incomplete, unmerged draft
schemas. Stored and browser profiles must contain every current choice and
classifier field; incomplete profiles are refused before publication. A host
holding incomplete draft profiles must reset/rebuild them outside the product
before installing the final detector extension. Verified import of an existing
native/managed setup and native-only onboarding remain supported.

Edits, reset and inclusion changes stay pending until Apply succeeds. Repeated
submission of one action ID returns that existing job, including after it
finishes. An explicit Retry or Reprocess creates a new action. Returning to the
page never restarts a job. Errors preserve the previously committed pair.

Native-only sites are not silently enrolled by installing the UI. Their existing
updater continues until an allowed viewer explicitly applies Filters. A managed
generation whose producing profile cannot be verified is frozen until a known
profile is rebuilt. This distinction preserves existing native-only operation
without claiming that its historical configuration is known.

## Architecture and installation

This integration is optional and uses Python 3.6+, Perl 5.20+, POSIX permissions
and `flock`, Apache's Unix-socket HTTP proxy, and a dedicated statistics account.
`tools/normalize_logs.py` reads configured Apache logs without modifying them.
The existing native/classifier tests are prerequisites for adopting this
publisher; its full native-accounting fixtures use the corrections in the
separate native-accounting PR.

1. Install the application tree read-only, create dedicated statistics and
   control-service accounts, and provision the protected runtime directories.
   The HTTP account gets no publisher, raw-log or mutable-history permissions.
2. Configure the publisher's root-owned JSON settings, without group/other
   write permission: `base`, `web`, `config`,
   `state`, `app`, `legacy_app`, `perl`, `perl_libraries`, `log`, `source_log`,
   `statistics_user`, `api_user`, `web_group`, and exact HTTPS
   `origins`. Site/log mappings remain in private `sites.json` and AWStats
   configuration. Each site's AWStats `DirIcons` must resolve to
   `/vstats/assets/icon`, where the publisher copies the release icons. Native
   AWStats runs must finish without warnings: any stderr output fails the
   publisher run and keeps the previously committed report/profile pair. Do not
   put machine configuration or credentials in Git. Keep `state` on the same
   filesystem as `web` and provide `/sbin/restorecon` (policycoreutils): each
   publication runs `restorecon -R` on its generation and renames it from
   `state` into `web/generations` before `current` changes. A missing or
   failing command, or a cross-filesystem layout, fails the run and keeps the
   prior report/profile pair.
3. Browser controls follow each site's native `AllowToUpdateStatsFromBrowser`:
   `1` displays editing, Preview and Apply & reprocess; `0` hides those actions
   and the API, worker and publisher reject browser mutations. Scheduled updates
   continue. There is no separate Filters account or login form. Existing web
   server restrictions authorize viewers; every allowed viewer can operate the
   controls for an enabled site.
   `AllowAccessFromWebToAuthenticatedUsersOnly=1` additionally requires the web
   server's authenticated `REMOTE_USER`; the native allowed-user list is checked
   case-insensitively. Configure the web server's protected realm on both reports
   and API when using this option. `__REMOTE_USER__` permits that authenticated
   user. The proxy must overwrite `X-VStats-Remote-User` from its real identity,
   including an empty value for anonymous requests; never pass a client identity
   header through. No new credentials are issued by Filters.
4. Run `publish-static-reports.py --bootstrap-ui --control-settings FILE` as
   root under the existing updater lock. This verifies an existing managed
   profile and republishes navigation without changing its native counters.
   An unverifiable managed import fails instead of inventing provenance.
5. Run `filters-server.py --settings FILE --socket-activation` as the control
   account with one systemd Unix listening socket accessible to Apache. Proxy
   `/vstats-control/` to that socket, preserve existing report-view restrictions,
   and overwrite `X-Forwarded-Proto` with the real request scheme and
   `X-VStats-Remote-User` with the server’s real `REMOTE_USER`. Never expose the
   private service directly. HTTPS, exact Origin and a CSRF token are required
   for changes; the browser uses the existing same-origin web authentication.
6. Run `filters-worker.py --settings FILE` as a separate root worker. It reads
   only structured, schema-validated spool actions, rereads the native browser
   permission and optional authentication rules, and invokes a fixed publisher command. The publisher demotes every
   native parser to the statistics account. No browser-provided shell commands
   or filesystem paths are accepted.
7. Point the existing scheduled updater at `publish-static-reports.py` with the
   same settings. Scheduled updates and UI jobs share the original updater lock.

The root publisher/worker writes a private sanitized `state/browser-policy.json`.
The worker refreshes it during its ordinary queue scan. The API checks source
file metadata (including includes) and refuses stale policy without reading
native configuration contents. Grant the control account traversal/stat access
to configuration/include parent directories, never native-config read access.
Changed files deny operations until refreshed, including during a long job.
The worker rereads permission before launching, and Apply checks again before
publication. Unknown/malformed flags fail closed. Includes follow the native
10-level limit; the policy reader additionally supports at most one MiB per
configuration file as a defensive bound. Environment variables in include names
are expanded from the root publisher/worker environment.

`--trial` builds and validates privately without publishing. `--verify-repeat`
checks native totals and history sections on repeated identical input.
`--lock-fd` is reserved for a root deployment wrapper holding that exact lock.

The publisher stages mutable histories, profiles and all four report views.
Publisher-owned `LogFile`, `DirData`, `PurgeLogFile=0` and `ArchiveLogRecords=0`
assignments follow native Includes, so included settings cannot redirect processing
or purge retained input. Filtered and verified views select their staged `VerifiedCrawlerEvidenceFile` after Includes, and a Filters-managed original view selects none; the original view of a site not managed by Filters retains its configured evidence choice.
Managed sites with native Includes replay every retained month on every run.
The processing cost grows with retained input; no capacity guarantee is made.
The publisher preserves the original main or verified configuration directory
as the base for relative Includes, including nested and parent-directory targets.
The statistics account reads these targets in place, so they need the same read
permission as for native command-line processing. No extra copy is made.
A manifest is complete before the single public report-generation symlink
changes. Readers, the API and subsequent updates resolve the profile through
that same pointer. Failed work cannot select a new profile with old reports.
Previous and current report generations are retained; older derived histories
and work products are pruned after a later successful commit. Corpus trees and
profile metadata remain. Unchanged source days are shared by hard link, but each
Preview and Apply first makes a full byte copy of that site's retained corpus
in `state/runs/<generation>/base/corpus/<site>/seed-*`. Preview baseline replays
and changed days can also create independent versions; superseded corpus trees
persist in older run bases. Each committed Apply's `seed-*` copy is also hard-linked into every later run base,
so removing unreferenced older corpus trees does not free it. Corpus copies are not reclaimed automatically.
Mutable native histories are copied. Size storage for these copies and set an
operator retention policy; this feature does not promise unlimited storage.
Before removing any unreferenced `state/runs/<generation>/base/corpus` tree,
verify that the current and previous committed manifests' `private_base` values,
their corpus pointers/receipts, and the configured original `base` do not refer
to it. Never delete original logs or a referenced corpus to free this space.
Sites added to `sites.json` after setup join as native-only and are not enrolled
in Filters until a profile is explicitly applied.
Their existing history is copied only if each history directory is a real
directory containing only regular statistics-account files of at most 64 MiB;
otherwise scheduled publication fails closed until the operator resolves it.
Existing incorrectly encoded history in sites not managed by Filters is not
migrated; managed views regenerate from retained input when their profile or a
native input bound by the replay cache changes. That cache does not bind native
`cgi-bin/lib/` modules other than `robots.pm`, or plugins; after changing only
those, run an explicit retained-input rebuild (Apply & reprocess).

## Capacity and evidence

Raw exclusion counts describe omitted log records, which may already be
non-viewed or ignored by AWStats. Publication audits replay both omitted-record
complements with the same native settings and show their viewed/non-viewed/ignored
breakdown in Impact. Older generations show this breakdown as unavailable;
reprocessing creates it. The extra logs and audit histories stay private, and
visitor/visit totals still come from the selected native history.


A behavior-enabled publisher run, including Preview, collects the registered
Google public crawler IP-range feed over verified HTTPS as root, at most once
per publisher process. After 30 archived retrievals in a UTC day (the 32-snapshot
day cap minus two bracketing snapshots), later runs retain the prior bundle. An already
overfull archived day still fails closed and needs an explicit operator decision
before reprocessing can resume; committed archives are never silently thinned or deleted.
No visitor data is sent. Only committed publications archive retrieved raw
snapshots and retrieval attestations; Preview and failed-run retrievals are
pruned with other work products after a later successful commit. The staged
evidence is frozen for both applied and proposed Preview profiles. Collection
failure leaves the previous valid bundle available without extending its
historical coverage.

The exporter defaults to strict failure. The publisher explicitly selects
`--capacity-fallback`: an unambiguous documented byte/record/group hard-max
refusal makes every dependent classifier/IP-policy layer inactive for the
affected site/UTC month. Required halo input is included in that decision.
The native signature setting and independent dated verified-crawler treatment
continue. Saved choices are unchanged, and later processing reevaluates readiness.
No limits are raised and no input is truncated. Lowered operator quotas,
malformed input, permission errors and failed audits remain failures.

Unavailable classifier results are labelled unavailable, never zero or inferred.
Per-filter match counts overlap and must not be summed as unique exclusions.
Native before/after visitors, visits, pages, hits and response-body bytes are
recomputed. Remaining visitors are not verified humans. Detection heuristics
have no measured precision/recall guarantee.

An externally pruned or rewritten managed corpus fails the scheduled coverage
guard; an explicit retained-input rebuild is required. The control plane does
not silently repair or discard source material to get a job through that guard.


WordPress query probing has its own filter choice, advanced key/path lists and
match count. It affects only the matching requests. The login browser-rotation
rule also accepts alternative browser-change or separated platform-switch
witnesses; only its original stronger conjunction can trigger IP/month
expansion. The IP policy checkbox therefore does not turn every new heuristic
into a whole-source exclusion. Existing saved profiles keep the new query
filter disabled until explicitly selected; Reset checks it.

Robots-file requests and successful content-page walks alone remain visible.
Self-declared CVE PoC tools follow the native crawler-signatures choice and do
not establish verified identity, malicious intent or exploitation.


Backdoor path probing and Protocol endpoint discovery each have a Filters
checkbox, advanced controls, match counts and review evidence. Their short
witnesses can include configured nearby homepage/favicon GET/HEAD requests;
clear `entry paths` to exclude explicit probes only. They never trigger the
whole-IP policy. The rules require corroborating probe paths/methods and
missing responses, with a declared tool also required for protocol discovery.
Successful protocol clients, ordinary page walks, robots-file requests and
shared browser signatures alone do not qualify. All thresholds are unvalidated
heuristics. Existing profiles preserve their policy until the new choices are
selected; Reset checks them and keeps configured lists.

## Scanner association and service discovery

Three additional choices are available: **Service-manifest discovery**,
**Operator-associated scanners**, and **Retrospective operator inference**.
The first two are selected for new profiles. Retrospective inference is always off on Reset/new
profiles. It needs selected UTC months in Advanced plus reprocessing. Its
comparison button opens a separate inferred report, clearly labelled as
unverified historical identity. Default reports stay unchanged.

Operator association requires offline, dated evidence for the exact address
and trustworthy client-address provenance. A current PTR/forward match does
not verify earlier requests. Without suitable evidence the filter abstains.
Service discovery flags only missing probes across independent manifest
families sharing source, vhost and observed agent in a short window. Neither
rule expands into whole-IP/month exclusion. Browser visits, robots.txt reads,
ordinary metadata and shared browser signatures alone stay counted.

**Current impact** and **Review** separate dated association, retrospective
candidates and service-manifest behavior. Native replays disclose how many
matched requests were already non-viewed. Per-class overlaps and exclusive
contributions are separate; visitor/session deltas are not apportioned among
rules. Use Preview, examine controls and native effects, then Apply/Reprocess.
Prior report generations remain available for undo.
## WordPress micro-probing and metadata requests

Two component checkboxes keep these choices separate. New profiles and Reset
select them.

**WordPress micro-probing** detects short, corroborated request episodes, using
the configured login, entry and POST/API paths. Installation discovery requires
HEAD requests at at least three distinct login locations, a login GET, and at
least two browser claims spanning two claimed platforms. The POST branch needs
at least three failing POSTs at three configured paths, including a configured
API endpoint, with the same diversity requirements. The default window is ten
seconds. These are exploratory heuristics, not calibrated probabilities.
Observed page/asset continuity in the same source/site window vetoes the episode
conservatively, including legitimate browsing behind a shared gateway. Only
witnessed login requests, failed POSTs and configured preceding entry requests
are affected; the rule never seeds source-IP/month expansion. Browser/platform
claims do not prove client identity or malicious intent.

**Metadata requests** removes matching GET/HEAD requests for robots.txt and
configured metadata paths, plus recognized XML/XML.gz sitemap names. It is a
reporting policy: a manual request for these URLs can also match. It does not
label an actor as a crawler, increase the suspected-automation union or expand
an exclusion to other requests from the source. Page requests remain eligible.
Turn off the checkbox to restore these hits and bytes when reprocessing retained
input. Request-ID inclusions can preserve an individual matching request.

The existing **Declared automation** option accepts curated explicit names.
Operators may configure InternetData.io and BitSightBot; these are unverified
declarations, not authenticated operator identities. InternetData describes its
automated robots/homepage scanning at <https://internetdata.io/scan>. A generic
browser string, missing assets, robots.txt alone and geography do not establish
crawler identity.
