# Pull Request

## Type of Change
- [ ] New blog post / case study
- [ ] New detection rule
- [ ] Detection rule tuning / false-positive reduction
- [ ] Tool release / update
- [ ] Bug fix
- [ ] Site / design / infrastructure
- [ ] Documentation

## Summary
<!-- 1-3 sentences describing the change. -->

## Pre-merge Checklist
- [ ] No customer-identifiable info, tenant IDs, or proprietary internal data
- [ ] IOCs in blog post text are defanged; raw IOCs only under `iocs/<campaign>/`
- [ ] MITRE ATT&CK technique IDs verified against attack.mitre.org
- [ ] Detection rules include `false_positives` and `tuning_notes` fields
- [ ] `jekyll build` succeeds locally
- [ ] Markdown lint passes: `npx markdownlint-cli2 "docs/_posts/**/*.md"`
- [ ] No secrets, keys, or credentials in the diff

## Related Issue(s)
<!-- Fixes #123 / Closes #456 -->
