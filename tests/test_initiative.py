"""Checks on the generated NSM GP-IKT 2.1 initiative. No Azure access is needed.

Usage: python3 -I tests/test_initiative.py -v
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARAM = re.compile(r"parameters\('([^']+)'\)")
GROUP = "NSM_GP-IKT_2.1_"


def load(name):
    return json.loads((ROOT / name).read_text())


class Initiative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.set = load("nsm-gp-ikt-2.1.policyset.json")
        cls.p = cls.set["properties"]
        cls.map = load("nsm-mcsb-map.json")
        cls.src = load(f"source/mcsb-{cls.map['mcsb_version']}.json")["properties"]
        cls.names = load("source/builtin-policies.json")["policies"]
        cls.gp = {m["id"]: m for m in json.loads((ROOT / "source" / "gp-ikt-2.1-measures.json").read_text())["measures"]}
        cls.arm = load("azuredeploy.json")
        cls.defs = cls.p["policyDefinitions"]

    def test_generated_files_are_current(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("build_initiative", ROOT / "build_initiative.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        policyset, measures, gp, names, src = mod.build()
        self.assertEqual(policyset, self.set, "run build_initiative.py")
        self.assertEqual(mod.template(policyset), self.arm, "run build_initiative.py")
        self.assertEqual(mod.coverage(policyset, measures, gp, names, src), (ROOT / "coverage.md").read_text(), "run build_initiative.py")

    def test_every_policy_is_copied_unchanged_from_microsofts_initiative(self):
        source = {d["policyDefinitionReferenceId"]: d for d in self.src["policyDefinitions"]}
        for d in self.defs:
            original = source[d["policyDefinitionReferenceId"]]
            for key in ("policyDefinitionId", "definitionVersion", "parameters"):
                self.assertEqual(d.get(key), original.get(key), d["policyDefinitionReferenceId"])

    def test_policy_ids_are_builtin_and_not_deprecated(self):
        for d in self.defs:
            prefix, guid = d["policyDefinitionId"].rsplit("/", 1)
            self.assertEqual(prefix, "/providers/Microsoft.Authorization/policyDefinitions")
            self.assertRegex(guid, r"^[0-9a-z]{8}(-[0-9a-z]{4}){3}-[0-9a-z]{12}$")
            self.assertIn(guid, self.names, f"{guid} is not in Microsoft's built-in definitions")
            self.assertFalse(self.names[guid]["deprecated"], guid)

    def test_reference_ids_are_unique(self):
        refs = [d["policyDefinitionReferenceId"] for d in self.defs]
        self.assertEqual(len(refs), len(set(refs)))

    def test_every_group_is_defined_named_after_a_measure_and_used(self):
        groups = [g["name"] for g in self.p["policyDefinitionGroups"]]
        self.assertEqual(len(groups), len(set(groups)))
        used = {g for d in self.defs for g in d["groupNames"]}
        self.assertEqual(used, set(groups), "a group without a policy, or a policy in an undefined group")
        for g in self.p["policyDefinitionGroups"]:
            mid = g["name"][len(GROUP):]
            self.assertTrue(g["name"].startswith(GROUP))
            self.assertIn(mid, self.gp)
            self.assertTrue(g["displayName"].startswith(mid + " "))
            self.assertEqual(g["category"].split(" ")[0], self.gp[mid]["principle_id"])
            self.assertLessEqual(len(g["displayName"]), 128)
        self.assertEqual({g[len(GROUP):] for g in groups}, set(self.map["measures"]))
        self.assertEqual(set(self.p["metadata"]["measures"]), set(self.map["measures"]))

    def test_parameters_are_exactly_those_referenced(self):
        used = set(PARAM.findall(json.dumps([d.get("parameters", {}) for d in self.defs])))
        self.assertEqual(used, set(self.p["parameters"]))
        for name, value in self.p["parameters"].items():
            self.assertEqual(value, self.src["parameters"][name], name)

    def test_required_parameters_of_each_builtin_are_passed(self):
        for d in self.defs:
            required = self.names[d["policyDefinitionId"].rsplit("/", 1)[1]]["required"]
            self.assertLessEqual(set(required), set(d.get("parameters", {})), d["policyDefinitionReferenceId"])

    def test_map_selects_what_the_groups_hold(self):
        by_group = {}
        for d in self.defs:
            for g in d["groupNames"]:
                by_group.setdefault(g[len(GROUP):], set()).add(d["policyDefinitionReferenceId"])
        ctrl = {}
        for d in self.src["policyDefinitions"]:
            for g in d["groupNames"]:
                ctrl.setdefault(g.rsplit("_", 1)[1], []).append(d["policyDefinitionReferenceId"])
        for mid, m in self.map["measures"].items():
            want = set()
            for link in m["links"]:
                self.assertIn(link["strength"], ("direkte", "delvis"))
                self.assertIn("tildelt omfang", link["scope"], f"{mid}: the scope must say it is the assigned scope")
                self.assertGreater(len(link["why"]), 20)
                self.assertIn(link["mcsb"], ctrl, f"{mid}: MCSB control without policies")
                want |= set(link.get("include") or [r for r in ctrl[link["mcsb"]] if r not in link.get("exclude", [])])
            self.assertEqual(by_group[mid], want, mid)
            self.assertEqual(self.p["metadata"]["measures"][mid]["strength"],
                             "direkte" if all(l["strength"] == "direkte" for l in m["links"]) else "delvis")

    def test_azure_policy_limits(self):
        # learn.microsoft.com/azure/governance/policy/overview, read 2026-11-11: 1000 policies, 400 parameters and
        # 1,048,576 bytes per initiative. The page lists no limit on groups; 1000 is this project's own ceiling.
        self.assertLessEqual(len(self.defs), 1000)
        self.assertLessEqual(len(self.p["parameters"]), 400)
        self.assertLessEqual(len(self.p["policyDefinitionGroups"]), 1000)
        self.assertLess(len(json.dumps(self.p, ensure_ascii=False).encode()), 1_048_576)
        self.assertLessEqual(len(self.set["name"]), 64)
        self.assertNotRegex(self.set["name"], r"[#<>%&:\\?/]|[. ]$")

    def test_metadata(self):
        md = self.p["metadata"]
        self.assertEqual(md["category"], "Regulatory Compliance")
        self.assertEqual(md["source"], f"Microsoft cloud security benchmark {self.src['version']}")
        self.assertRegex(md["version"], r"^\d+\.\d+\.\d+$")
        self.assertEqual(self.p["policyType"], "Custom")
        # Shown in Defender for Cloud > Regulatory compliance.
        self.assertEqual(self.p["metadata"]["ASC"], "true")
        self.assertEqual(self.p["metadata"]["category"], "Regulatory Compliance")

    def test_arm_template(self):
        t = self.arm
        self.assertTrue(t["$schema"].endswith("managementGroupDeploymentTemplate.json#"))
        definition, assignment = t["resources"]
        self.assertEqual(definition["type"], "Microsoft.Authorization/policySetDefinitions")
        self.assertEqual(assignment["type"], "Microsoft.Authorization/policyAssignments")
        self.assertEqual(assignment["condition"], "[parameters('assign')]")
        self.assertIs(t["parameters"]["assign"]["defaultValue"], False)
        self.assertEqual(assignment["properties"]["enforcementMode"], "DoNotEnforce")
        self.assertLessEqual(t["parameters"]["assignmentName"]["maxLength"], 24)
        # Azure requires an identity because two policies have a deployment in their rule. It must stay without
        # rights: the template grants it no role.
        self.assertEqual(assignment["identity"], {"type": "SystemAssigned"})
        self.assertNotIn("Microsoft.Authorization/roleAssignments", [r["type"] for r in t["resources"]])

        # Inside the definition every expression is escaped, so Resource Manager leaves it for Azure Policy.
        def strings(v):
            if isinstance(v, dict):
                for x in v.values():
                    yield from strings(x)
            elif isinstance(v, list):
                for x in v:
                    yield from strings(x)
            elif isinstance(v, str):
                yield v
        inner = list(strings(definition["properties"]))
        self.assertFalse([s for s in inner if s.startswith("[") and not s.startswith("[[")], "unescaped expression in the definition")
        self.assertTrue([s for s in inner if s.startswith("[[parameters('")])

        # Unescaping gives back the policy set exactly.
        def unescape(v):
            if isinstance(v, dict):
                return {k: unescape(x) for k, x in v.items()}
            if isinstance(v, list):
                return [unescape(x) for x in v]
            return v[1:] if isinstance(v, str) and v.startswith("[[") else v
        self.assertEqual(unescape(definition["properties"]), self.p)


if __name__ == "__main__":
    unittest.main()
