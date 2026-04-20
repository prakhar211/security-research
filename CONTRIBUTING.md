# Contributing

Thanks for your interest in contributing to this security research repository.

## What You Can Contribute

- **Detection rules** — new LogScale / KQL / DataPrime / Sigma rules mapped to MITRE ATT&CK
- **Tuning improvements** — reducing false positives on existing detections
- **Tool improvements** — bug fixes, new features, documentation
- **Typos, broken links, formatting fixes** — always welcome

## What You Should NOT Submit

- Weaponized exploit code
- Customer-identifiable information in incident writeups
- Raw credentials, API keys, or PII (of any kind)
- Detection rules you do not have rights to publish

## Workflow

1. Open an issue first for new posts, new detections, or significant changes.
   Use the issue templates under `.github/ISSUE_TEMPLATE/`.
2. Fork the repo, branch from `main`.
3. Make changes, following the schemas documented in `detections/README.md` and `iocs/README.md`.
4. Run local checks:
   ```bash
   cd docs && bundle exec jekyll build
   npx markdownlint-cli2 "docs/_posts/**/*.md"
   ```
5. Open a PR using the template. CI will run secrets scanning and markdown linting.

## Detection Rule Contributions

- Every rule MUST include: `id`, `name`, `description`, `mitre_attack`, `platform`, `data_sources`, `query`, `false_positives`, `tuning_notes`.
- Use the schema documented in [`detections/README.md`](detections/README.md).
- Include test / validation steps (atomic red team commands, manual repro).

## IOC Contributions

- Defang in blog posts; publish raw in `iocs/<campaign>/indicators.csv`.
- Follow the CSV schema in [`iocs/README.md`](iocs/README.md).

## Code of Conduct

Be professional. This is a technical security research space — disagreements
about detection logic, threat models, or methodology are welcome; personal
attacks are not.

## License

By contributing, you agree that:
- Code contributions are released under the [MIT License](LICENSE).
- Written content contributions (blog posts) are released under [CC BY-SA 4.0](LICENSE-CONTENT.md).
