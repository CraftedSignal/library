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

The library is automatically synced every 6 hours via GitHub Actions. Curated Sigma rules are ingested directly from commit-pinned checkouts of [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), [huntresslabs/threat-intel](https://github.com/huntresslabs/threat-intel), and [depalmar/ai-dfir-toolkit](https://github.com/depalmar/ai-dfir-toolkit), with quality gates, source provenance, duplicate handling, and per-source license attribution. The AI DFIR Toolkit adds vendor-neutral coverage for LLM applications, MCP servers, ML supply chains, AI infrastructure, AI-powered insider threats, and RAG/vector database attacks.

First-party rules use `source: craftedsignal`. Refreshes preserve these entries and give them precedence over API and curated-upstream records with the same ID. Curated-source collisions resolve in this order: SigmaHQ, AI DFIR Toolkit, then Huntress.

The Huntress and AI DFIR Toolkit syncs currently import Sigma detections only. IOC CSVs, YARA signatures, Suricata rules, tools, and other artifact formats remain excluded until the library has first-class schemas for them. Other mirrored aggregators that duplicate well-known upstream sources also remain excluded.

## License

Detection rules are provided by their respective authors. See individual entries for attribution.
