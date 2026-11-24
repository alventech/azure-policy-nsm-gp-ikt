## What and why

<!-- A changed link: the NSM measure, the MCSB control or policy, the strength, and the reason (NSM's text, Microsoft's documentation). -->

## Checklist

- [ ] Changed only `nsm-mcsb-map.json` by hand, and regenerated the rest (Python 3, no packages):
      `python3 -I build_initiative.py` (macOS, Linux), `py -I build_initiative.py` (Windows).
- [ ] `python3 -I tests/test_initiative.py -v` passes
- [ ] A line in `CHANGELOG.md` for anything a user notices
- [ ] No tenant data (tenant or subscription IDs, resource names, compliance exports) in the pull request
