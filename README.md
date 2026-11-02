# PrivTrace

[Leer en espanol](README.es.md)

PrivTrace is a read-only Windows privilege-escalation path analyzer. It correlates the current token, privileges, groups, services, scheduled tasks, executable paths, and effective permissions to identify actionable security conditions.

A `CONFIRMED` result means the rule's required conditions were observed. It does **not** mean exploitation or privileged execution was performed.

## How it works

PrivTrace collects read-only evidence through Windows APIs, including the current token, services, scheduled tasks, processes, executable paths, and effective permissions.

It correlates that evidence with its rule catalog to identify privilege-escalation conditions. The default output shows actionable findings, while `--verbose` and JSON preserve the complete diagnostic context.

PrivTrace does not attempt exploitation or modify the analyzed system.

## Download

Download the latest x64 or x86 executable from [GitHub Releases](https://github.com/y0naldez/PrivTrace/releases/latest).

- Use **x64** on most modern Windows systems.
- Use **x86** only when a 32-bit executable is required.
- Compare the downloaded file against `PrivTrace-v1.1.0-SHA256.txt` from the same release.

PrivTrace is distributed as a single executable. No installation or third-party package is required.

Verify a downloaded executable from the directory containing the release files:

```powershell
Get-FileHash .\PrivTrace-v1.1.0-win-x64.exe -Algorithm SHA256
Get-Content .\PrivTrace-v1.1.0-SHA256.txt
```

The computed hash must exactly match the line for the selected architecture.

## Quick start

Run the default high-signal analysis:

```powershell
.\PrivTrace.exe
```

Run with Spanish console output:

```powershell
.\PrivTrace.exe -es
```

Export a structured JSON report:

```powershell
.\PrivTrace.exe --json report.json
```

## Common options

| Option | Purpose |
| --- | --- |
| `-es`, `--es` | Show natural Spanish console output. |
| `--verbose` | Include unknown, ruled-out, and diagnostic details. |
| `--processes` | Show observed processes and service associations. |
| `--binaries` | Show execution paths and effective permissions. |
| `--json <file>` | Export the complete structured report. |
| `--rule <PT-xxx>` | Evaluate one rule. |
| `--rule-info <PT-xxx>` | Show information about one rule. |
| `--category <name>` | Filter rules by category. |
| `--list-rules` | List all available rules. |
| `--help` | Show command-line help. |

Options can be combined:

```powershell
.\PrivTrace.exe -es --verbose --json report.json
```

## Third-party software and version context

PrivTrace also inventories selected third-party software that can be relevant during a local privilege-escalation assessment. It correlates running processes, installation paths, PE metadata, Windows services, and the embedded software-profile catalog. When an approved local source is available, it reports the observed product version and its provenance.

Version sources can include:

- PE product or file-version metadata from the observed executable.
- The Windows uninstall registry for a corroborated installation.
- Product-specific local metadata, such as XAMPP's `properties.ini`.

A representative concise result can look like this:

```text
INTERESTING SOFTWARE

[1] Apache HTTP Server / XAMPP
    Process    : C:\xampp\apache\bin\httpd.exe
    Service    : Apache2.4
    Version    : 8.3.4-0
    Source     : C:\xampp\properties.ini
    Escalation : PT-013, PT-016
```

This information helps an analyst prioritize investigation. For example, PrivTrace can show that a third-party application is active, identify the service account and executable involved, report a locally observed version, and correlate writable paths or weak service permissions with existing PT rules.

Example interpretations:

- `TeamViewer 15.x` with `Escalation: NOT VERIFIED` is inventory context only; the version does not imply a vulnerability.
- `XAMPP 8.x` with `PT-013` means PrivTrace correlated its service executable with effective write access and a privileged service identity. It does not mean the executable was modified or run.
- A product with `Version: UNKNOWN` may still produce a permission finding, because ACL and service evidence are independent from version discovery.

The software name or version alone never creates an escalation finding. PrivTrace does not assume that an old version is vulnerable, does not map versions to CVEs, and does not query an online vulnerability database. If product identity or version provenance cannot be verified, it reports the value as `UNKNOWN` rather than guessing. Use `--verbose` or JSON to inspect identification confidence, version source, signature state, paths, PIDs, services, and pending conditions.

## Default English console output

English is the default console language. The normal view is intentionally concise and prioritizes actionable evidence. A representative service finding looks like this:

```text
[HIGH] Service: KiteService
    Account   : LocalSystem
    Binary    : C:\Program Files\Kite\KiteService.exe
    PT-013    : FILE_REPLACEMENT (CONFIRMED)
    Execution : CONDITIONAL_EXECUTION
    CanStart  : Yes
    Runtime protection: UNKNOWN
```

How to interpret it:

- `Account: LocalSystem` identifies the configured privileged service identity.
- `PT-013` identifies the rule that produced the finding.
- `FILE_REPLACEMENT (CONFIRMED)` means the current token's effective permissions satisfy the rule's file-replacement condition.
- `CanStart: Yes` means the current token was observed to have service-start access.
- `CONDITIONAL_EXECUTION` means PrivTrace did not replace the executable, start the service, or demonstrate privileged code execution.
- `Runtime protection: UNKNOWN` means protections outside the collected evidence still require manual review.

Therefore, `CONFIRMED` describes verified detection conditions, not successful exploitation. Run `--verbose` for ruled-out and unknown checks, evidence traces, collector diagnostics, software provenance, and pending conditions.

## Spanish console output

The `-es` projection uses ASCII-only text so it remains readable in legacy Windows consoles and redirected output.

```text
[ALTA] Servicio: KiteService
    Cuenta de ejecucion       : LocalSystem
    Puede iniciar el servicio? : SI (confirmado)
    Puede detener el servicio? : SI (confirmado)
    Puede escribir el binario? : SI (confirmado)
    Puede reemplazarlo?        : SI (confirmado)
    Se probo la ejecucion?     : NO; la ejecucion privilegiada sigue siendo condicional
    Proteccion en ejecucion    : REVISAR MANUALMENTE (no evaluada)
```

The language flag changes console presentation only. Rule identifiers, detection logic, JSON properties, and machine-readable values remain stable.

## Understanding results

| State | Meaning |
| --- | --- |
| `CONFIRMED` | All required conditions defined by the rule were observed. |
| `POTENTIAL` | Positive evidence exists, but additional conditions remain unverified. |
| `INFORMATIONAL` | Relevant context without an actionable escalation claim. |
| `RULED_OUT` | A required condition was demonstrably false. |
| `UNKNOWN` | Evidence was unavailable, inaccessible, or incomplete. |

Severity describes potential impact. Confidence describes evidence quality. `CONDITIONAL_EXECUTION` means PrivTrace detected a permission or configuration path but did not modify, restart, or execute the target.

For service findings:

- `FILE_WRITE_DATA` means the current user can modify the existing executable's content.
- `FILE_REPLACEMENT` means the observed permissions allow the executable to be replaced.
- `CanStart: Yes` confirms the current user can start the service.
- Runtime protection remains unknown unless it was independently evaluated.

## Safety and limitations

PrivTrace does not stop or start services, launch tasks, replace files, change ACLs or registry values, extract secrets, download rules, or send telemetry.

Administrative privileges are not required. If Windows denies access to evidence, PrivTrace preserves the result as `UNKNOWN` instead of assuming that the condition is safe or vulnerable.

Use PrivTrace only on systems you own or are authorized to assess.

## Requirements

- Windows.
- .NET Framework 4.0 or a compatible installed runtime.
- No network connection or administrative privileges are required to start PrivTrace.
