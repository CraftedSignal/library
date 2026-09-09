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

The library is automatically synced every 6 hours via GitHub Actions. SigmaHQ rules are ingested directly from a commit-pinned checkout with quality gates, lifecycle categories, provenance, and DRL attribution. Other mirrored aggregators that duplicate well-known upstream sources remain excluded.

## License

Detection rules are provided by their respective authors. See individual entries for attribution.
