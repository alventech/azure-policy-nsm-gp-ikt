"""Build the Azure Policy initiative for NSM GP-IKT 2.1 from Microsoft's own cloud security benchmark initiative.

Usage: python3 -I build_initiative.py

Reads  source/mcsb-<version>.json   Microsoft cloud security benchmark, the built-in initiative, pinned
       source/builtin-policies.json display names and required parameters of the built-in policies it uses
       nsm-mcsb-map.json            which MCSB controls, and which of their policies, support which NSM clause
       source/gp-ikt-2.1-measures.json  NSM's measures: IDs, principles and titles
Writes nsm-gp-ikt-2.1.policyset.json  the custom policySetDefinition (name and properties)
       azuredeploy.json               ARM template for a management group: the definition, and optionally an assignment
       coverage.md                    measure, MCSB controls, policies and strength

No policy GUID, definition version or parameter is typed here: each policy entry is copied from Microsoft's file
with its parameter wiring, and only the group names are replaced. The script stops on anything that would not deploy.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import nsm_links  # noqa: E402

MCSB_VERSION = "57.60.0"
SRC = HERE / "source" / f"mcsb-{MCSB_VERSION}.json"
NAMES = HERE / "source" / "builtin-policies.json"
MAP = HERE / "nsm-mcsb-map.json"
GP = HERE / "source" / "gp-ikt-2.1-measures.json"
REPO = "https://github.com/alventech/azure-policy-nsm-gp-ikt"
NAME = "nsm-gp-ikt-2.1"
GROUP = "NSM_GP-IKT_2.1_"
API = "2023-04-01"
# GUID-shaped, but not strictly hex: Microsoft's own ID for "Transparent Data Encryption on SQL databases should be
# enabled" is 17k78e20-9358-41c9-923c-fb736d382a12. Every ID must also exist in source/builtin-policies.json.
ID = re.compile(r"^/providers/Microsoft\.Authorization/policyDefinitions/[0-9a-z]{8}(-[0-9a-z]{4}){3}-[0-9a-z]{12}$")
PARAM = re.compile(r"parameters\('([^']+)'\)")
# Azure Policy limits, learn.microsoft.com/azure/governance/policy/overview, read 2026-11-11. No group limit is listed there.
MAX_POLICIES, MAX_PARAMETERS, MAX_BYTES, MAX_GROUPS = 1000, 400, 1_048_576, 1000


def order(mid):
    return [int(p) for p in mid.split(".")]


def refs_of(link, by_ctrl):
    """The reference IDs one link of the map selects from its MCSB control."""
    ctrl = link["mcsb"]
    assert ctrl in by_ctrl, f"MCSB control {ctrl} has no policies in {SRC.name}"
    assert not ("include" in link and "exclude" in link), f"{ctrl}: use include or exclude, not both"
    assert link["strength"] in ("direkte", "delvis") and link["scope"].strip() and link["why"].strip(), f"{ctrl}: strength, scope and why are required"
    have = by_ctrl[ctrl]
    for ref in link.get("include", []) + link.get("exclude", []):
        assert ref in have, f"{ref} is not a policy of MCSB control {ctrl}"
    return link.get("include") or [r for r in have if r not in link.get("exclude", [])]


def build():
    src = json.loads(SRC.read_text())["properties"]
    assert src["version"] == MCSB_VERSION, f"{SRC.name} is version {src['version']}"
    nsm_map = json.loads(MAP.read_text())
    assert nsm_map["mcsb_version"] == MCSB_VERSION, "the map was written for another MCSB version"
    gp = {m["id"]: m for m in json.loads(GP.read_text())["measures"]}
    names = json.loads(NAMES.read_text())["policies"]

    by_ctrl = {}
    for d in src["policyDefinitions"]:
        for g in d["groupNames"]:
            by_ctrl.setdefault(g.rsplit("_", 1)[1], []).append(d["policyDefinitionReferenceId"])

    member, measures = {}, {}
    for mid in sorted(nsm_map["measures"], key=order):
        assert mid in gp, f"{mid} is not a measure in {GP.name}"
        links = nsm_map["measures"][mid]["links"]
        refs = []
        for link in links:
            for ref in refs_of(link, by_ctrl):
                if ref not in refs:
                    refs.append(ref)
        assert refs, f"{mid} selects no policy"
        for ref in refs:
            member.setdefault(ref, []).append(GROUP + mid)
        scopes = list(dict.fromkeys(l["scope"] for l in links))
        measures[mid] = {
            "strength": "direkte" if all(l["strength"] == "direkte" for l in links) else "delvis",
            "scope": scopes[0] if len(scopes) == 1 else "Azure-ressurser i tildelt omfang",
            "mcsb": list(dict.fromkeys(l["mcsb"] for l in links)),
            "clauses": sorted({l["clause"] for l in links if l["clause"]}),
            "refs": refs,
        }

    definitions, used = [], set()
    for d in src["policyDefinitions"]:
        ref = d["policyDefinitionReferenceId"]
        if ref not in member:
            continue
        assert ID.match(d["policyDefinitionId"]), f"{ref}: {d['policyDefinitionId']} is not a built-in policy definition ID"
        assert d["policyDefinitionId"].rsplit("/", 1)[1] in names, f"{ref}: not a built-in policy in {NAMES.name}"
        info = names[d["policyDefinitionId"].rsplit("/", 1)[1]]
        assert not info["deprecated"], f"{ref} is deprecated"
        missing = [p for p in info["required"] if p not in d.get("parameters", {})]
        assert not missing, f"{ref}: required parameters {missing} are not passed"
        used.update(PARAM.findall(json.dumps(d.get("parameters", {}))))
        definitions.append({**d, "groupNames": member[ref]})
    refs = [d["policyDefinitionReferenceId"] for d in definitions]
    assert len(refs) == len(set(refs)), "duplicate policyDefinitionReferenceId"
    assert set(refs) == set(member), f"not found in the source: {set(member) - set(refs)}"
    for p in used:
        assert p in src["parameters"], f"parameter {p} is not defined in {SRC.name}"

    groups = [{
        "name": GROUP + mid,
        "category": f"{gp[mid]['principle_id']} {gp[mid]['principle']}",
        "displayName": f"{mid} {gp[mid]['title'].rstrip('.')}",
        "description": f"NSMs grunnprinsipper for IKT-sikkerhet 2.1, tiltak {mid}. Les tiltaket hos NSM: {nsm_links.measure_url(gp[mid])}",
    } for mid in measures]
    defined = {g["name"] for g in groups}
    assert all(set(d["groupNames"]) <= defined for d in definitions), "a policy names a group that is not defined"
    assert all(len(g["displayName"]) <= 128 for g in groups)

    policyset = {"name": NAME, "properties": {
        "displayName": "NSM grunnprinsipper for IKT-sikkerhet 2.1",
        "description": "Innebygde Azure Policy-definisjoner gruppert etter tiltakene i NSMs grunnprinsipper for IKT-sikkerhet 2.1. "
                       f"Generert fra Microsoft cloud security benchmark {MCSB_VERSION}. Dekker bare det Azure Policy kan måle; "
                       "resten måles i Entra ID, Microsoft 365 og Intune eller attesteres. "
                       f"Fellesskapsprosjekt (MIT), ikke laget eller godkjent av NSM eller Microsoft. Kilde: {REPO}",
        "policyType": "Custom",
        # ASC "true" onboards the initiative to Defender for Cloud > Regulatory compliance as its own standard,
        # laid out group by group (needs a paid Defender plan on the subscription, such as Defender CSPM).
        "metadata": {"category": "Regulatory Compliance", "ASC": "true", "version": nsm_map["initiative_version"],
                     "source": f"Microsoft cloud security benchmark {MCSB_VERSION}", "framework": nsm_map["framework"],
                     "measures": {mid: {k: v for k, v in m.items() if k != "refs"} for mid, m in measures.items()}},
        "parameters": {p: src["parameters"][p] for p in src["parameters"] if p in used},
        "policyDefinitionGroups": groups,
        "policyDefinitions": definitions,
    }}
    body = json.dumps(policyset["properties"], ensure_ascii=False)
    assert len(definitions) <= MAX_POLICIES and len(used) <= MAX_PARAMETERS and len(groups) <= MAX_GROUPS, "over an Azure Policy limit"
    assert len(body.encode()) < MAX_BYTES, "the definition is larger than Azure accepts in one request"
    return policyset, measures, gp, names, src


def escape(value):
    """A string that starts with '[' is an expression to Resource Manager. '[[' keeps it for Azure Policy to evaluate."""
    if isinstance(value, dict):
        return {k: escape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [escape(v) for v in value]
    return "[" + value if isinstance(value, str) and value.startswith("[") else value


def template(policyset):
    set_id = "[extensionResourceId(managementGroup().id, 'Microsoft.Authorization/policySetDefinitions', parameters('initiativeName'))]"
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-08-01/managementGroupDeploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {"description": "NSM GP-IKT 2.1 as an Azure Policy initiative. Generated by build_initiative.py; do not edit by hand."},
        "parameters": {
            "initiativeName": {"type": "string", "defaultValue": policyset["name"], "maxLength": 64},
            "assign": {"type": "bool", "defaultValue": False, "metadata": {"description": "Also assign the initiative to this management group, in audit only (DoNotEnforce)."}},
            "assignmentName": {"type": "string", "defaultValue": policyset["name"], "maxLength": 24},
        },
        "resources": [
            {"type": "Microsoft.Authorization/policySetDefinitions", "apiVersion": API, "name": "[parameters('initiativeName')]",
             "properties": escape(policyset["properties"])},
            {"condition": "[parameters('assign')]", "type": "Microsoft.Authorization/policyAssignments", "apiVersion": API,
             "name": "[parameters('assignmentName')]",
             "dependsOn": [set_id],
             # Azure refuses an assignment without a managed identity when any policy in it has a deployment in its
             # rule, even at AuditIfNotExists and DoNotEnforce. Two do: the Windows and Linux compute security
             # baselines (guest configuration). The identity gets no role assignment, so it can change nothing.
             "location": "[deployment().location]",
             "identity": {"type": "SystemAssigned"},
             "properties": {"displayName": policyset["properties"]["displayName"], "policyDefinitionId": set_id, "enforcementMode": "DoNotEnforce",
                            "description": "Måler Azure-ressursene mot NSM GP-IKT 2.1. Håndheves ikke."}},
        ],
        "outputs": {"policySetDefinitionId": {"type": "string", "value": set_id}},
    }


def coverage(policyset, measures, gp, names, src):
    nsm_map = json.loads(MAP.read_text())
    props = policyset["properties"]
    by_ref = {d["policyDefinitionReferenceId"]: d for d in props["policyDefinitions"]}

    def effect(d):
        """The effect a policy gets when the initiative is assigned with its default parameters."""
        for key, v in d.get("parameters", {}).items():
            if key.lower() == "effect":
                m = PARAM.search(str(v["value"]))
                value = str(src["parameters"][m.group(1)].get("defaultValue") if m else v["value"])
                return value[:1].upper() + value[1:]
        return "policy default"

    off = [r for r, d in by_ref.items() if effect(d).lower() == "disabled"]
    lines = [
        "# Coverage of NSM GP-IKT 2.1 in Azure Policy", "",
        "Generated by `build_initiative.py` from `nsm-mcsb-map.json`. Do not edit by hand.", "",
        f"- {len(measures)} of {len(gp)} NSM measures have at least one policy "
        f"({sum(1 for m in measures if gp[m]['in_alert'])} of them are in [NSM's alert of 27.10.2026]({nsm_links.ALERT})).",
        f"- {len(by_ref)} built-in policies of the {len(src['policyDefinitions'])} in Microsoft cloud security benchmark {MCSB_VERSION}, "
        f"{len(props['parameters'])} initiative parameters.",
        f"- {sum(1 for m in measures.values() if m['strength'] == 'direkte')} measures are linked *direkte*, "
        f"{sum(1 for m in measures.values() if m['strength'] == 'delvis')} *delvis*.",
        f"- {len(off)} policies are switched off by Microsoft's default parameters and give no result until they are switched on "
        "in the assignment. They are marked (off) below.", "",
        "*Direkte*: the setting is what the clause asks for. *Delvis*: evidence for the clause within the stated scope.", "",
        "| Measure | In alert | MCSB | Policies | Strength | Scope |", "| --- | --- | --- | --- | --- | --- |",
    ]
    for mid, m in measures.items():
        lines.append(f"| [{mid}]({nsm_links.measure_url(gp[mid])}) {gp[mid]['title'].rstrip('.')} | {'yes' if gp[mid]['in_alert'] else ''} | "
                     f"{', '.join(m['mcsb'])} | {len(m['refs'])} | {m['strength']} | {m['scope']} |")
    for mid, m in measures.items():
        lines += ["", f"## {mid} {gp[mid]['title'].rstrip('.')}", ""]
        for link in nsm_map["measures"][mid]["links"]:
            clause = f", clause {link['clause']}" if link["clause"] else ""
            lines.append(f"- **{link['mcsb']}**{clause}, {link['strength']}: {link['why']}")
        lines += ["", "| Policy | Reference ID | Default effect |", "| --- | --- | --- |"]
        for ref in m["refs"]:
            d = by_ref[ref]
            name = names[d["policyDefinitionId"].rsplit("/", 1)[1]]["displayName"]
            lines.append(f"| {name} | `{ref}` | {effect(d)}{' (off)' if ref in off else ''} |")
    lines += ["", "## Left out", "", "| MCSB | Why |", "| --- | --- |"]
    lines += [f"| {x['mcsb']} | {x['why']} |" for x in nsm_map["left_out"]]
    lines += ["", nsm_map["not_in_azure_policy"], ""]
    return "\n".join(lines)


def main():
    policyset, measures, gp, names, src = build()
    (HERE / f"{NAME}.policyset.json").write_text(json.dumps(policyset, ensure_ascii=False, indent=1) + "\n")
    (HERE / "azuredeploy.json").write_text(json.dumps(template(policyset), ensure_ascii=False, indent=1) + "\n")
    (HERE / "coverage.md").write_text(coverage(policyset, measures, gp, names, src))
    p = policyset["properties"]
    print(f"{NAME}: {len(measures)} measures, {len(p['policyDefinitionGroups'])} groups, {len(p['policyDefinitions'])} policies, "
          f"{len(p['parameters'])} parameters, {len(json.dumps(p, ensure_ascii=False).encode()) // 1024} KB")


if __name__ == "__main__":
    main()
