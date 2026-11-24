# Azure Policy initiative for NSM GP-IKT 2.1

A custom Azure Policy initiative that groups Microsoft's built-in policies by the measures in NSM's
[grunnprinsipper for IKT-sikkerhet 2.1](https://nsm.no/regelverk-og-hjelp/rad-og-anbefalinger/grunnprinsipper-for-ikt-sikkerhet/)
(GP-IKT 2.1, NSM's ICT Security Principles). It reports on the Azure resources in the assigned scope for 20 of
NSM's measures. Entra ID,
Microsoft 365, Defender and Intune are measured by the
[NSM GP-IKT 2.1 Maester pack](https://github.com/alventech/maester-pack-nsm-gp-ikt), and the rest needs an owner's
attestation.

**A free community project.** Free to use and change under the MIT licence, and open to contributions from anyone.
It is not a product of NSM, Microsoft or any company, is not made, reviewed or endorsed by NSM, and comes with no
support agreement or warranty.

Version 0.1.0, tested in a lab tenant in November 2026; see [What has been tested](#what-has-been-tested).

## What is in it

| | |
| --- | --- |
| NSM measures with at least one policy | 20 of 118 (9 of the 21 GP-IKT measures that [NSM's alert of 27.10.2026](https://nsm.no/aktuelt/nsm-hever-det-nasjonale-cyberrisikonivaet-til-hoyt) points to) |
| Built-in policies | 132, all taken from Microsoft cloud security benchmark 57.60.0 (216 policies) |
| Initiative parameters | 111, copied from Microsoft with their defaults |
| Groups | One per measure, named `NSM_GP-IKT_2.1_<measure>`, for example `NSM_GP-IKT_2.1_2.3.1` |
| Link strength | 8 measures *direkte*, 12 *delvis* |

[coverage.md](coverage.md) lists every measure with its policies, the reason for each link, and what was left out.

## How it is built

Microsoft maintains the built-in initiative "Microsoft cloud security benchmark" (MCSB), where each built-in policy
is grouped under an MCSB control such as PV-6 or NS-2. This initiative reuses that work:

1. `source/mcsb-57.60.0.json` is a pinned copy of Microsoft's initiative.
2. `nsm-mcsb-map.json` says which MCSB controls, and which of their policies, support which NSM clause. Each link
   has a strength, a scope and a sentence on the NSM text it rests on. This is the only hand-written file.
3. `build_initiative.py` copies each selected policy entry from Microsoft's file unchanged (policy ID, definition
   version, parameter wiring) and replaces only the group names.

No policy GUID is typed by hand. When Microsoft publishes a new MCSB version, replace the source file, update the
version in the map and the generator, and run it again; the generator stops if a policy named in the map is gone.

```bash
python3 -I build_initiative.py          # writes the policy set, the ARM template and coverage.md
python3 -I tests/test_initiative.py -v  # 11 checks, no Azure access needed
```

| File | What it is |
| --- | --- |
| `nsm-mcsb-map.json` | The mapping. Edit this. |
| `build_initiative.py` | The generator. Python 3.9 or later, standard library only. |
| `nsm_links.py` | Links from a measure to its text on nsm.no. |
| `nsm-gp-ikt-2.1.policyset.json` | Generated: name and properties of the policy set definition. |
| `azuredeploy.json` | Generated: ARM template for a management group. |
| `coverage.md` | Generated: coverage and reasons. |
| `source/mcsb-57.60.0.json`, `source/builtin-policies.json` | Microsoft's initiative, and the names and required parameters of the built-in policies it uses. Copied from [Azure/azure-policy](https://github.com/Azure/azure-policy) (MIT, © Microsoft Corporation). |
| `source/gp-ikt-2.1-measures.json` | NSM's measures: IDs, principle and category names, titles, priority and whether NSM's alert points to the measure. NSM's full text stays on nsm.no. |
| `tests/test_initiative.py` | Checks on the generated files. |

## Strength

- *Direkte*: the setting is what the NSM clause asks for. Example: "System updates should be installed on your
  machines" for 2.3.1.
- *Delvis*: evidence for the clause within a stated scope, or Microsoft's check is stricter or narrower than
  NSM's wording. Example: Azure Backup on virtual machines for 2.9.1, which asks for a plan.

A link that would be a stretch is left out, and the measure then has no policy. A measure's result from Azure
Policy is never the result for the whole measure: it covers Azure resources in the assigned scope only.

## Deploy

Run `validate` and `what-if` first; they change nothing.

```bash
az deployment mg validate --management-group-id <id> --location norwayeast --template-file azuredeploy.json
az deployment mg what-if  --management-group-id <id> --location norwayeast --template-file azuredeploy.json
az deployment mg create   --management-group-id <id> --location norwayeast --template-file azuredeploy.json
```

That creates the definition only. To also assign it to the management group, in audit only:

```bash
az deployment mg create --management-group-id <id> --location norwayeast --template-file azuredeploy.json --parameters assign=true
```

The assignment uses `enforcementMode: DoNotEnforce`, so no policy blocks or changes a resource; the policies only
report compliance. Two policies, the Windows and Linux compute security baselines (guest configuration, 2.3.4 and
2.3.5), have a deployment in their rule. They default to AuditIfNotExists, but Azure still refuses the assignment
without a managed identity (`ResourceIdentityRequired`). The assignment therefore has a system-assigned identity
with **no role assignment**: it cannot deploy or change anything. Do not grant it a role unless you want
remediation.

Deploying needs Resource Policy Contributor on the management group. The definition name is `nsm-gp-ikt-2.1`.

## See the results

- **Azure Policy > Compliance** shows the initiative's compliance per policy and resource.
- **Defender for Cloud > Regulatory compliance**: the initiative's metadata has `"ASC": "true"` and the category
  `Regulatory Compliance`, so it can show as its own standard, laid out by NSM measure. This needs a paid Defender
  plan on the subscription, such as Defender CSPM, and appears only after the first compliance evaluation, and only
  when at least one resource is assessed. Microsoft calls this the legacy custom-standard mechanism; it is the one
  that keeps the grouping per measure.

Five policies are switched off by Microsoft's default parameter values and give no result until they are switched
on in the assignment: NSG on subnets, storage account network restriction, expiry on Key Vault keys and secrets,
and certificate validity period. coverage.md marks them "(off)".

## What it does not cover

- 98 measures have no policy. Governance, plans, contracts, network equipment, OT and clients cannot be read from
  Azure Policy.
- MFA (2.6.7), end-user rights (2.6.4), application control (2.3.2), host firewall (2.4.4) and disk encryption on
  clients (2.7.3) are measured in Entra ID and Intune by the
  [Maester pack](https://github.com/alventech/maester-pack-nsm-gp-ikt).
- Kubernetes workload rules, customer-managed keys, private link, DDoS protection and guest accounts are left out
  on purpose. coverage.md gives the reason for each.
- Only policies that are in MCSB are candidates. A built-in policy outside MCSB that fits an NSM clause better
  would have to be added to the map with its own source.

## What has been tested

Offline, by `build_initiative.py` and the tests:

- Every policy ID exists in Microsoft's built-in definitions (github.com/Azure/azure-policy, read 2026-11-11) and
  none is deprecated.
- Every policy entry equals Microsoft's entry in MCSB 57.60.0, and every required parameter of each built-in is
  passed.
- Groups, parameters and reference IDs are consistent; the ARM template escapes policy expressions and unescapes
  back to the policy set exactly.
- Size: 132 policies, 111 parameters and about 105 KB, against Azure's limits of 1000 policies, 400 parameters and
  1,048,576 bytes per initiative (learn.microsoft.com/azure/governance/policy/overview, read 2026-11-11). That page
  lists no limit on the number of groups.
- The definition name follows Azure's naming rule for policy set definitions.

In a lab tenant, in November 2026: `validate`, `what-if` and the deployment with `assign=true` at the tenant root
management group. The deployed definition had 132 policies in 20 groups; the assignment was DoNotEnforce, and its
identity had no role assignment.

Not tested yet: that the standard appears in Defender for Cloud > Regulatory compliance.

The mapping is the author's reading of NSM's text. Nobody at NSM or Microsoft has reviewed it.

## The 2022 community initiative

[stalejohnsen/NSM_GP-IKT_2_0_policyinitative](https://github.com/stalejohnsen/NSM_GP-IKT_2_0_policyinitative) is an
example initiative for GP-IKT 2.0 from 2022, with 18 policies in 9 groups (2.3.1, 2.5.1, 2.6.7, 2.7.2, 2.7.3,
2.7.4, 3.1.1, 3.1.3, 3.2.5), read in November 2026.

| | 2022 initiative | This one |
| --- | --- | --- |
| NSM version | 2.0 | 2.1 |
| Measures | 9 | 20 |
| Policies | 18, listed by hand | 132, generated from MCSB |
| Reason per link | no | yes, with strength and scope |
| Tracks Microsoft's changes | no | regenerate from a new MCSB version |

Its group 2.6.7 held the policies for MFA on subscription accounts. Microsoft has since removed those from MCSB,
and MFA is measured in Entra ID here. Its groups 2.7.3 and 3.2.5 are left out here because the policies behind
them do not show what those measures ask for.

The policy ID `17k78e20-9358-41c9-923c-fb736d382a12`, in both initiatives, looks like a typing error, but it is
Microsoft's real ID for "Transparent Data Encryption on SQL databases should be enabled". The generator therefore
accepts IDs that are GUID-shaped but not strictly hexadecimal, and checks each one against Microsoft's list.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Never attach compliance exports or
screenshots with your tenant's resource names or IDs to a public issue; describe the setup instead.

## Licence

[MIT](LICENSE). NSM's principles are NSM's; this repository links to them on nsm.no and holds only their IDs, principle and category names, titles, priority and whether NSM's alert points to the measure. The files under `source/` from Microsoft are under Microsoft's MIT licence.
