# Documented robot and agent signatures

This update adds specific HTTP `User-Agent` declarations checked against operator documentation on **10 November 2026**. It extends the existing native robot database; it does not replace the browser database or import another project's full regex catalogue.

A matching name is **unverified user-agent evidence**. A client can copy it. It neither authenticates an operator nor establishes malicious activity. Several listed agents fetch a page on a person's behalf rather than crawl the web independently.

## New declarations

| HTTP agent name | Documented purpose | Primary source |
| --- | --- | --- |
| `OAI-AdsBot` | OpenAI ad landing-page fetcher | [Operator documentation](https://developers.openai.com/api/docs/bots) |
| `Amzn-SearchBot` | Amazon search crawler | [Operator documentation](https://developer.amazon.com/amazonbot) |
| `Amzn-User` | Amazon user-directed fetcher | [Operator documentation](https://developer.amazon.com/amazonbot) |
| `KimiBot` | Kimi training crawler | [Operator documentation](https://www.kimi.ai/policies/kimi-crawlers) |
| `Kimi-SearchBot` | Kimi search crawler | [Operator documentation](https://www.kimi.ai/policies/kimi-crawlers) |
| `Kimi-User` | Kimi user-directed fetcher | [Operator documentation](https://www.kimi.ai/policies/kimi-crawlers) |
| `MistralAI-Index` | Mistral search crawler | [Operator documentation](https://docs.mistral.ai/robots) |
| `MistralAI-Training` | Mistral training crawler | [Operator documentation](https://docs.mistral.ai/robots) |
| `Google-Agent` | Google hosted browser agent | [Operator documentation](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) |
| `Google-GeminiNotebook` | Gemini Notebook source fetcher | [Operator documentation](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) |
| `Google-NotebookLM` | NotebookLM source fetcher (legacy token) | [Operator documentation](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) |
| `Google-Pinpoint` | Google Pinpoint source fetcher | [Operator documentation](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) |
| `Google-CWS` | Chrome Web Store metadata fetcher | [Operator documentation](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) |
| `GoogleMessages` | Google Messages preview fetcher | [Operator documentation](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) |
| `Google-Read-Aloud` | Google Read Aloud fetcher | [Operator documentation](https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers) |
| `Claude-Agent` | Anthropic hosted browser agent | [Operator documentation](https://support.claude.com/en/articles/18234133-how-do-anthropic-hosted-browsers-identify-themselves-when-they-browse-the-web-on-a-user-s-behalf) |

`Google-NotebookLM` is a historical HTTP token retired in August 2026, retained here for analysis of older logs. It is not presented as a current Google product name.

## Existing fetchers on mobile and tablet user agents

The following existing native IDs also participate in the narrowly scoped device check. Their rules, descriptions and saved history IDs are preserved; they still require their existing `/` suffix.

| Declared name | Existing saved ID | Primary source |
| --- | --- | --- |
| `ChatGPT-User` | `ChatGPT-User/` | [Operator documentation](https://developers.openai.com/api/docs/bots) |
| `Claude-User` | `Claude-User/` | [Operator documentation](https://support.claude.com/en/articles/8896518-does-anthropic-crawl-data-from-the-web-and-how-can-site-owners-block-the-crawler) |
| `MistralAI-User` | `MistralAI-User/` | [Operator documentation](https://docs.mistral.ai/robots) |
| `Perplexity-User` | `Perplexity-User/` | [Operator documentation](https://docs.perplexity.ai/guides/bots) |

An explicitly named agent no longer receives the ordinary mobile/tablet exemption simply because its HTTP header also contains Android, iPhone or iPad. Ordinary browser strings continue through the existing device logic.

## Matching, controls and saved history

The new rules match complete, ASCII case-insensitive agent names. They permit a following version slash, whitespace, semicolon, closing parenthesis or end of string. Prefixes and hostname-like suffixes such as `NotKimiBot` and `KimiBot.example` do not match the new declaration. A different existing generic rule can still classify such a request under its existing semantics.

The sixteen new entries form the first block of level 1 rules. This prevents a generic word such as `crawler` inside a documentation URL from taking the name of a specifically declared new agent. Existing entries keep their relative order and values. Multi-marker headers follow native rule order.

`LevelForRobotsDetection=1` or higher enables these additions. At level 0, the helper does not override device detection and the normal disabled-robot behavior remains. In installations with the Filters interface, its existing native-crawler control continues to govern native exclusions. This PR adds no new switch, behavioral filter, IP/geography rule or HTTP access restriction.

New IDs contain no literal whitespace and retain their bounded regex, including its inline ASCII matching mode, through native history write/reload. Existing IDs are unchanged. The inline mode requires Perl 5.14 or later. Report labels show the declared name and its operator documentation, without claiming sender verification.

The optional traffic classifier's configured token lists, verified-provider checks and behavior rules are separate and unchanged. Native recognition and the classifier's unknown-agent labels therefore need not have the same coverage.

## Reprocessing

Installing source code does not itself rewrite existing history. Recognition changes when logs are processed again. In the managed publisher integration, `robots.pm` contributes to the native cache fingerprint: its next normal scheduled publication can reparse **all retained months**, generate replacement private histories/caches and reports, then publish the matching report/profile generation atomically. Newly recognized agents may reduce visitor totals under the existing native-crawler policy. No manual historical replay is part of this PR's deployment.

The rollout requires an explicit decision on that scheduled rebuild and protected recovery. Restoring the application pointer after a later publication does not by itself restore the old reports. Recovery must keep the report/derived-state pair consistent and preserve all source-corpus rows accumulated since deployment.

## Selection and limits

Discovery compared the native registry with public upstream material, including Matomo Device Detector at [`ec3a5d0b53bf76d93e7d025dcac4c69caf30ffbc`](https://github.com/matomo-org/device-detector/commit/ec3a5d0b53bf76d93e7d025dcac4c69caf30ffbc) and official AWStats develop at [`a2ab5339b7d113348390f0c376efa65f10cbf528`](https://github.com/eldy/awstats/commit/a2ab5339b7d113348390f0c376efa65f10cbf528). These are recorded discovery points, not a promise of exhaustive coverage. The new literal patterns are independently written from the linked operator documentation; no Matomo regex catalogue or fixture code is imported.

Names without sufficiently clear operator HTTP-header documentation in this pass were left out, including ChatGPT-Browser, DeepseekBot, xAI-Bot, Groq-Bot, Manus-User, NovaAct and AmazonBuyForMe. The older GoogleAgent-Mariner and GoogleAgent-Search documentation routes no longer supplied a current HTTP-header definition. FirecrawlAgent was documented as a robots.txt matching token rather than clearly as an HTTP header. No new entry is added merely for a robots.txt-only product control such as Google-Extended or Applebot-Extended; existing database entries remain unchanged.

This is recognition maintenance, not an estimate of real-world bot-detection accuracy. Synthetic boundary/native-history checks establish their tested cases only.
