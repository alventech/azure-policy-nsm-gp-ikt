# Changelog

## 0.1.0

The first public release: a free community project under the MIT licence.

- **132 built-in Azure policies** from Microsoft cloud security benchmark 57.60.0, grouped by **20 measures** of
  NSM's ICT Security Principles 2.1 (GP-IKT), one policy definition group per measure (`NSM_GP-IKT_2.1_<measure>`).
- **Every link has a strength (direkte, delvis), a scope and a reason**, in `nsm-mcsb-map.json`; see
  [coverage.md](coverage.md).
- **Generated, not typed:** policy IDs, versions and parameters are copied from Microsoft's initiative, so a new MCSB
  version is a rebuild.
- **Audit only:** the ARM template can assign the initiative to a management group with `DoNotEnforce`, and its
  managed identity has no role.
- **Defender for Cloud:** the initiative can show as its own standard under Regulatory compliance, laid out by NSM
  measure (needs a paid Defender plan).
