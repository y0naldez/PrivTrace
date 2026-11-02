# Adding rules

1. Add declarative metadata to `data/knowledge/rules/rules.xml`: a unique ID, name, category, severity, registered evaluator, version, verification state, description, required/optional/invalidating conditions, limitations, recommendation, and valid references.
2. For a simple rule that fits an existing evaluator, extend its SID/privilege mapping or object predicate. For a genuinely new correlation, implement a specialized evaluator rather than reducing it to string matching.
3. Preserve the distinction between severity and confidence. Return `UNKNOWN` for missing data, `RULED_OUT` only for a demonstrated false precondition, and `CONFIRMED` only when all enumerated mandatory conditions are observed.
4. Add synthetic positive, negative, and unknown tests. Add regression cases for every parser, permission, or correlation defect found.
5. Update documentation and source metadata. Do not add a lab name until its exact technique and configuration are verified from a public source.

The catalog validator currently requires exactly PT-001 through PT-024. To grow to 50 or 100 rules, version the catalog schema and change that bootstrap constraint deliberately, with tests for the new expected range. Avoid silently weakening validation.

Recommended next set: AlwaysInstallElevated; writable MSI deployment source; auto-logon secret exposure (report-only, no extraction); weak registry autorun target; writable startup folder target; DLL search-order path; PATH directory hijack; writable COM server registration; weak named-pipe ACL; weak process/service token boundary; vulnerable driver inventory; shadow-copy exposure; unattended-install artifact permissions; insecure credential-file ACL; IIS application-pool identity correlation; writable webroot with privileged worker extension path; weak WMI permanent consumer permissions; weak event-log service object permissions; writable Group Policy startup script target; and domain GPO modification rights. Each needs separate version, OS, ACL, and mitigation research before implementation.
