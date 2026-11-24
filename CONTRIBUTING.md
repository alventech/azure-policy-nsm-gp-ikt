# Contributing

This is a free community project. Anyone can open an issue or a pull request: a better link between an NSM
measure and a policy, a link that should be left out, or a fix to the generator.

## Disagreeing with a link

The links are a reading of NSM's text, with a strength (*direkte* or *delvis*), a scope and a reason for each in
`nsm-mcsb-map.json`. If you think a link is wrong, open an issue with the measure, the MCSB control or policy, and
why, from NSM's text and Microsoft's documentation. The maintainer decides and writes the reason in the issue.

## Rules

- **Edit the map, not the output.** `nsm-mcsb-map.json` is the only hand-written file. The policy set, the ARM
  template and `coverage.md` are generated.
- **No hand-typed policy IDs.** Policies come from Microsoft's MCSB initiative in `source/`.
- **Every link has a reason.** `strength`, `scope` and `why` are required; a link that would be a stretch is left out
  and listed under `left_out`.
- **No NSM text beyond IDs, principle and category names, titles, priority and whether NSM's alert points to the measure.** Link to nsm.no instead.
- **Audit only.** The template must keep the assignment at DoNotEnforce, with no role for its identity.

## Before a pull request

```bash
python3 -I build_initiative.py && python3 -I tests/test_initiative.py -v && git status --short
```

Commit the regenerated files with the map change. Never include deployment output, tenant or subscription IDs.
