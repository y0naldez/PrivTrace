# Initial rules

| ID | Rule | Correlation |
|---|---|---|
| PT-001 | SeImpersonatePrivilege | Token presence/state; technique preconditions remain pending |
| PT-002 | SeAssignPrimaryTokenPrivilege | Token presence/state and companion-condition warning |
| PT-003 | SeBackupPrivilege | Token presence/state; no protected read attempted |
| PT-004 | SeRestorePrivilege | Token presence/state; no write attempted |
| PT-005 | SeDebugPrivilege | Token presence/state; protected-process constraints noted |
| PT-006 | SeTakeOwnershipPrivilege | Token presence/state; no ownership change |
| PT-007 | SeLoadDriverPrivilege | Token presence/state; signing/policy constraints noted |
| PT-008 | SeManageVolumePrivilege | Token presence/state; not direct escalation |
| PT-009 | Server Operators | Enabled, non-deny-only SID `S-1-5-32-549` |
| PT-010 | Backup Operators | Enabled, non-deny-only SID `S-1-5-32-551` |
| PT-011 | DnsAdmins | Resolved scoped token group; no universal fixed SID |
| PT-012 | Print Operators | Enabled, non-deny-only SID `S-1-5-32-550` |
| PT-013 | Writable Service Binary | Exact executable write plus privileged service identity |
| PT-014 | Weak Service Configuration Permissions | Effective `SERVICE_CHANGE_CONFIG` plus privileged identity |
| PT-015 | Unquoted Service Path | Ambiguous path, concrete candidate permission, privileged identity |
| PT-016 | Writable Service Executable Directory | Directory create right plus privileged identity; replacement is not assumed |
| PT-017 | Writable Scheduled Task Binary | Enabled task, exact binary write, higher principal |
| PT-018 | Weak Scheduled Task Permissions | Relevant task descriptor right plus higher principal |
| PT-019 | Writable Scheduled Task Script | Enabled task, exact script write, higher principal |
| PT-020 | Scheduled Task Execution Path Hijacking | Relative/ambiguous action, controllable target, higher principal |
| PT-021 | AlwaysInstallElevated | Both HKLM and HKCU Windows Installer policy values equal 1 |
| PT-022 | Event Log Readers | Enabled, non-deny-only SID `S-1-5-32-573`; no log contents collected |
| PT-023 | SeTcbPrivilege | Token presence/state; token/authentication preconditions remain pending |
| PT-024 | Print Spooler Impersonation Surface | Running privileged Spooler plus enabled SeImpersonatePrivilege |
| PT-025 | SeCreateTokenPrivilege | Token presence/state; token-creation inputs and API preconditions remain pending |
| PT-026 | Weak Service Registry Configuration Permissions | SCM-derived service key plus effective registry mutation right and privileged service identity |
| PT-027 | Writable Privileged ServiceDll | Privileged shared-process service, configured ServiceDll, existence/replacement ACL, explicit CONFIGURED relation |

Privilege and group rules normally produce `POTENTIAL`, because capability presence alone is not a complete path. Service, task, and policy rules produce `CONFIRMED` only after their enumerated cross-object conditions are present. PT-026 keeps a create-subkey-only case at `POTENTIAL`. PT-027 confirms an existing writable configured DLL but never claims it was loaded; a missing plantable DLL or indirect control remains `POTENTIAL`. Access-denied or missing security data produces `UNKNOWN`, never a fabricated negative.
