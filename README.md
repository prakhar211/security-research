# Security Research & Detection Engineering

Independent security research, incident case studies, detection-as-code, and open-source security tooling by **Prakhar Gupta** — Senior Cloud Security Analyst / Shift Lead, Coralogix SRC MDR.

> Blog site: published from `docs/` via GitHub Pages.

## What's In This Repository

| Path | Purpose |
|------|---------|
| `docs/` | Jekyll blog source — incident case studies, detection writeups, tool releases |
| `detections/` | Detection-as-code library: LogScale, KQL, DataPrime, Sigma |
| `iocs/` | Machine-readable IOC feeds (CSV + STIX 2.1) per campaign |
| `tools/` | Open-source security utilities |
| `.github/workflows/` | CI: Pages deploy, secrets scanning, markdown linting |

## Quickstart (local dev)

```bash
cd docs/
bundle install
bundle exec jekyll serve --livereload
# Site at http://localhost:4000/security-research/
```

## Content Types

- **Incident Case Studies** — sanitized investigations (AiTM, supply chain, cloud compromise)
- **Detection Engineering** — production hunting queries with tuning notes
- **Tool Releases** — open-source security utilities
- **Threat Hunt Playbooks** — structured methodologies mapped to MITRE ATT&CK
- **Threat Intelligence** — campaign analysis, actor profiling

## Licenses

- **Code** (`detections/`, `tools/`, site source): [MIT](LICENSE)
- **Blog content** (`docs/_posts/`): [CC BY-SA 4.0](LICENSE-CONTENT.md)

## Responsible Disclosure

See [responsible_disclosure.md](responsible_disclosure.md).

## Citation

If you use detection rules or research from this repository, please cite it — see [CITATION.cff](CITATION.cff).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
