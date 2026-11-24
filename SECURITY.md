# Security

The initiative only groups Microsoft's built-in Azure Policy definitions. The template assigns it with
`enforcementMode: DoNotEnforce`, and the assignment's managed identity has no role assignment, so it cannot block,
deploy or change anything. Grant that identity a role only if you want remediation.

## Reporting a vulnerability

Do not open a public issue. Report it privately through the repository's GitHub security advisories
("Report a vulnerability").

## Data in results

Compliance results contain resource names, subscription IDs and tenant IDs. Do not attach them to public issues;
describe the setup instead.
