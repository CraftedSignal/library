# CraftedSignal Community Detection Library

A curated collection of community-contributed detection rules in Sigma, SPL, and KQL formats.

## Structure

```
entries/
  sigma/    # Sigma detection rules
  spl/      # Splunk SPL queries
  kql/      # Microsoft KQL queries
library.index.yaml   # Index of all entries (without query content)
```

Each entry is a YAML file containing the detection rule, metadata, MITRE ATT&CK mappings, and references.

## Sync

The library is automatically synced every 6 hours via GitHub Actions. Curated Sigma rules are ingested directly from commit-pinned checkouts of [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) and [huntresslabs/threat-intel](https://github.com/huntresslabs/threat-intel), with quality gates, source provenance, duplicate handling, and per-source license attribution.

The Huntress sync currently imports Sigma detections only. IOC CSVs, YARA signatures, tools, and other artifact formats remain excluded until the library has first-class schemas for them. Other mirrored aggregators that duplicate well-known upstream sources also remain excluded.

## License

Detection rules are provided by their respective authors. See individual entries for attribution.
