# Cyberonik public risk data

Source data for [Cyberonik’s cyber risk monitor](https://cyberonik-website.vercel.app/cyber-risk).

The scheduled workflow checks CISA’s Known Exploited Vulnerabilities catalogue, CISA security alerts, FIRST EPSS scores and the sources behind the page’s reviewed research benchmarks. It runs at **00:23, 08:23 and 16:23 UTC** every day. GitHub scheduling can be delayed; the dataset records actual checks.

## Data and provenance

- `data/latest.json`: validated snapshot, source dates and independent feed health.
- `scripts/benchmarks.json`: reviewed annual figures, source URLs, reporting periods and verification anchors.
- `scripts/core.mjs`: parsers, validation and last-known-good behaviour.
- `scripts/collect.mjs`: bounded source fetching and snapshot publication.
- `scripts/core.test.mjs`: failure, validation and parser checks.
- [Workflow history](https://github.com/ujaved-oss/cyberonik-risk-data/actions/workflows/refresh.yml): actual runs and results.

This repository contains only public-source data and collection code. It does not contain the Cyberonik website application, customer information or credentials. The workflow uses GitHub’s temporary token only to commit its data snapshot to this repository. Standard hosted runners for public repositories are free; no paid services are configured.

## Reading the figures

KEV totals count vulnerabilities, not attacks or victims. Catalogue addition dates are not attack dates. EPSS is a probability forecast for exploitation activity against a vulnerability in the next 30 days, not a forecast of a particular company’s breach. FIRST is the source of EPSS scores.

IBM, WEF and FBI IC3 figures retain their published periods and study or reporting populations. Annual reported losses are not a real-time global loss counter. FBI descriptor categories may overlap with crime types and must not be summed. Source checks verify a reviewed publication; changed or newer annual publications require review before replacing a figure.

Failed checks retain prior valid data with the original successful-check time. Missing feeds remain unavailable, never zero. A checked source that is more than 12 hours old is marked overdue on the website. The website fetches the latest snapshot with a five-minute cache and has a labelled deployment snapshot if this repository is unreachable.

## Operations

Run the workflow manually from the Actions tab when needed. Changes to the collector trigger a run; snapshot commits do not trigger a loop. A partial source failure saves the health information and then marks the workflow failed. Maintainers should review failed runs and annual-publication review flags. GitHub can disable scheduled workflows after prolonged inactivity; normal snapshot commits provide repository activity, but the timestamps and overdue warnings remain the operational check.

Local run with Node.js 24:

```sh
node --test scripts/core.test.mjs
node scripts/collect.mjs --previous data/latest.json --output data/latest.json --config scripts/benchmarks.json
```

Source content retains its publisher’s terms. CISA KEV data is published under CC0; EPSS attribution is provided. Publisher names identify sources and do not imply a partnership or endorsement.
