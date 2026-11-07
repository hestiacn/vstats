# Filters for static vstats reports

The optional static publisher adds a **Filters** menu beside Basic, Guide,
Reference, Integration and Developer. Native reports keep their existing layout;
filter settings, explanations, previews, comparisons and review tables are in
Filters. Settings affect statistics, not access to the website.

## Using it

* **Settings:** native crawler signatures, verified crawler evidence, broad
  probing, configured endpoint probing, rapid content-path scanning, and
  distributed login probing. New intended settings are checked by default.
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

Anonymous history actors mean permitted browser access, not an authenticated identity.
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
persist in older run bases. Corpus copies are not reclaimed automatically.
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
