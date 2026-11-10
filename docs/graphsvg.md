# Optional SVG charts and diagnostic maintenance

The `graphsvg` plugin renders the existing AWStats ShowGraph data as inline SVG. It adds no analytics rules and does not change native histories, totals or filtering. Existing vstats charts remain the default.

## Enable SVG charts

Add `LoadPlugin="graphsvg"` to the site's AWStats configuration and regenerate its HTML reports. Disable other ShowGraph plugins, including `graphgooglechartapi` and `graphapplet`, first. Loading competing graph plugins is unsupported. Remove the setting and regenerate reports to restore the native charts; a log/history rebuild is unnecessary.

Time charts show the native series and their supplied scales, with bandwidth formatted as bytes. SVG pie hooks receive raw per-entry counts, while other graph plugins retain their existing rounded-percentage inputs. Pie percentages describe only the displayed entries, as stated beneath each pie; they are not percentages of the entire site's traffic. The country map hook becomes a ranking of the top 15 countries by hits. Native tables remain available for the complete values. Presentation markup in titles and browser/OS display names is reduced to plain text before XML escaping; filenames, addresses, extensions and cluster names retain their literal text, and each chart has a title and text labels. No chart data is sent to an external service, and no chart JavaScript is required. This applies to the plugin; other site/report assets retain their existing configuration.

## Diagnostics and existing DNS protection

CLI error diagnostics, including malformed-log diagnostics, go to stderr. HTML report and CGI error responses stay on stdout. For CLI HTML generation with `-output`, error text is written into the HTML on stdout and stderr can be empty; callers must check the nonzero exit status. Log samples and log filenames in HTML format-error responses are escaped as data. The existing three-argument, read-only DNS-cache open is retained and covered by a regression test; it is not a newly introduced security fix.

## Provenance

Adapted from [paneologist/AWStats](https://github.com/paneologist/AWStats/tree/release-8.0-paneologist.1), GNU GPL version 3 or later:

- [Inline SVG plugin](https://github.com/paneologist/AWStats/commit/1abd522b1e5b4c50866968e84d4a24247bbaec4e).
- [Diagnostic stream routing](https://github.com/paneologist/AWStats/commit/5d2e79b6539458daf2d4400b9dd04584b0e22731), adapted to vstats' modern error renderer.
- [DNS-cache safe open](https://github.com/paneologist/AWStats/commit/5267c75b90ebd22bb5cc0cdc304f9593a3b21725), already present in the vstats base.

The port namespaces internal helpers, adds accessible chart titles, accepts finite scientific numeric values, handles a single positive pie slice correctly and labels pie shares with their displayed-subset denominator.
